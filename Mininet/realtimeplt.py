import networkx as nx
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
from ryu.topology.api import get_switch
import time


'''
TODO: breve commentario, fo io

This file contains all the functions we use to plot data real-time. It's imported in our Total_revolution.py and used as follows:
    >>>  import reltimeplt as rtp
    >>>  rtp.throughput_plotter(self, pos)


'''


colors_list = [ 'royalblue', 'darkorange', 'olivedrab', 'indianred', 'mediumvioletred',
                'sandybrown', 'tomato', 'firebrick', 'midnightblue', 'orange', 'deepskyblue',
                'yellowgreen', 'forestgreen', 'darkgreen', 'greenyellow', 'seagreen',
                'mediumseagreen', 'crimson', 'lightseagreen', 'teal', 'navy', 'rebeccapurple',
                'chocolate', 'dodgerblue', 'cornflowerblue', 'goldenrod', 'slategrey', 'darkorchid'
                ]

switch_options = {
    'node_color': 'royalblue',
    'node_size': 400
}

host_options = {
    'node_color': 'slategrey',
    'node_size': 400,
    'node_shape': 's'
}

pie_labels = 'No active flows', 'Below the threshold', 'Over the threshold'
pie_colors = 'cornflowerblue','yellowgreen','tomato'



def refresh_figure(figure):
    fig = figure
    fig.canvas.draw_idle()
    time.sleep(0.01)            # sleep + flush_events invece che pause, secondo stackOverflow e' meglio, piu' efficiente
    fig.canvas.flush_events()


def thr_table_and_bar_chart_plotter(self, LINK_THRESHOLD, MAGNITUDE):
    """Flow's throughput on each link: table and histogram."""
    fig = plt.figure(5)
    fig.canvas.set_window_title("Real-time links' throughput")
    # Clear the current figure
    fig.clf()
    ax = fig.add_subplot(111)
    rows_labels = self.table_rows_labels
    columns_labels = self.table_columns_labels
    columns_labels = tuple(columns_labels)
    data = self.table_data
    y_values = np.arange(0, (LINK_THRESHOLD*1.5)/MAGNITUDE, (LINK_THRESHOLD/5)/MAGNITUDE)
    n_rows = len(data)
    x_ax = np.arange(len(columns_labels))
    bar_width = 0.4
    spare_width = (1 - bar_width)/2
    # Initialize the vertical-offset for the stacked bar chart
    y_offset = np.zeros(len(columns_labels))
    # Add title and labels
    ax.set_xticks([])  # No ticks
    ax.set_yticks(y_values, ['%d' % val for val in y_values])
    ax.set_ylabel("Throughput [MBps]")
    plt.title("Links' usage")
    ax.set_xlim(-spare_width, len(x_ax)-spare_width)
    # Get the colors from a palette
    try:
        colors = colors_list[0:len(rows_labels)]
    except IndexError:
        self.logger.info("Cannot plot. If you want to plot, you have to define more colors in the colors_list")
    # Plot the bars and create the text labels for the table
    cell_text = []
    for row in range(n_rows):
        plt.bar(x_ax, data[row], bar_width, bottom=y_offset, color=colors[row])
        y_offset = y_offset + data[row]
        cell_text.append(['%d' % x for x in data[row]])
    # Plot the threshold
    ax.axhline(LINK_THRESHOLD/MAGNITUDE, color='black', linestyle='--')
    # Add the table at the bottom of the axes
    if(data and columns_labels and rows_labels):
        the_table = plt.table(cellText=cell_text,
                            rowLabels=rows_labels,
                            rowColours=colors,
                            colLabels=columns_labels,
                            loc='bottom')
        # Adjust layout to make room for the table
        plt.subplots_adjust(left=0.2, bottom=0.2)
        fig.savefig('name_table', dpi=300, format='png')
    else:
        return
    refresh_figure(fig)


def thr_plotter(self, SLEEP, MAGNITUDE, MAG_STR, LINK_THRESHOLD):
    """Plot real-time throughput on each link."""
    x_max ,y_max = 0, 0
    t, tmp_links_usg, links_labels = [], [], []
    fig = plt.figure(1)
    # Clear the current figure
    fig.clf()
    ax = fig.add_subplot(111)
    ax.set_xlabel("Time [seconds]") 
    ax.set_ylabel("Throughput")
    for link in sorted(self.edge_stats.iterkeys()):        
        t = range(0, len(self.edge_stats[link].src_port_stats['throughputs_array'])*SLEEP, SLEEP)
        x_max = len(self.edge_stats[link].src_port_stats['throughputs_array'])
        lbl = "(s{0}, s{1})".format(link[0], link[1])       # Labels: (s1, s2), (s2,s3), etc.
        links_labels.append(lbl)
        ax.plot(t, self.edge_stats[link].src_port_stats['throughputs_array'], label=lbl, linewidth=2)
        #ax.legend(fancybox=True, framealpha=0.5)        # Slows down the program
        tmp_links_usg.append(self.edge_stats[link].src_port_stats['throughputs_array'])     # To print the peak
    '''
    try:
        # If the topology hasn't been created yet, `tmp_links_usg` is an empty list and so np.max(tmp_links_usg) raises an error
        y_max = np.max(tmp_links_usg)   # Peak, can be below the threshold
        ax.text(x_max, y_max+3, "{0} {1}".format(round(float(y_max)/MAGNITUDE, 2), MAG_STR), horizontalalignment='left', verticalalignment='center', fontdict={'size':6, 'color':'green' if y_max < LINK_THRESHOLD else 'red'})
    except ValueError:  # Raised if `tmp_links_usg` is empty.
        #self.logger.info("Topology not started yet.")
        pass
    '''
    # Plot the threshold
    ax.axhline(LINK_THRESHOLD, color='black', linestyle='--')
    refresh_figure(fig)


def total_thr_pie_charts_plotter(self, LINK_THRESHOLD):
    """Plots two pie charts: one for the instantaneous total throughput and one for the average one."""
    idle_perc, below_perc, over_perc = 0, 0, 0      # Percentages
    idle, below, over = 0, 0, 0     # Number of _ connections
    total_no = 0    # Total number of links
    no_data_yet = False

    for link in sorted(self.edge_stats.iterkeys()):
        try:
            if self.edge_stats[link].src_port_stats['throughput'] <= 1000:
                idle = idle + 1.0
                self.logger.debug("No TCP/UDP connections active.")
            elif self.edge_stats[link].src_port_stats['throughput'] < LINK_THRESHOLD:
                below = below + 1.0
                self.logger.debug("Below link's threshold.")
            else:
                over = over + 1.0
                self.logger.info("Over link's threashold.")
            total_no = total_no + 1.0
        except IndexError:
            self.logger.info("dovrebbe succedere se si crea la topologia ma non si fa in tempo ad aggiornare links_usage, che e' lista vuota")
            no_data_yet = True

    if (not self.edge_stats or no_data_yet):
        self.logger.debug("Empty link list, topology not started yet")
        total_no = 1.0
        idle = 1.0
    # Calculate percentages
    idle_perc = (idle/total_no)*100
    below_perc = (below/total_no)*100
    over_perc = (over/total_no)*100
    self.net_percentages[0].append(idle_perc)
    self.net_percentages[1].append(below_perc)
    self.net_percentages[2].append(over_perc)
    # Calculate the mean values
    idle_slice = np.mean(self.net_percentages[0])
    below_slice = np.mean(self.net_percentages[1])
    over_slice = np.mean(self.net_percentages[2])
    #self.logger.info("Mean percentages -- {0}%%  {1}%%  {2}%%\n".format(idle_perc,below_perc,over_perc))
    fig = plt.figure(3)
    # Clears the current figure
    fig.clf()

    # First subplot --- average links' congestion
    sizes = [idle_slice, below_slice, over_slice]
    # Highlight over the threshold slice
    explode = (0, 0, 0.2)
    ax = fig.add_subplot(2, 2, 1)
    ax.pie(sizes, explode=explode, autopct='%1.1f%%', shadow=True, startangle=90, colors=pie_colors)
    ax.axis('equal')    # Equal aspect ratio ensures that pie is drawn as a circle
    ax.legend(pie_labels, title="Links' status", bbox_to_anchor=(0.85,1.025), loc="upper left")
    ax.set(aspect="equal", title="Avg links' congestion")
    #self.logger.info("New percentages -- {0}%%  {1}%%  {2}%%".format(idle_perc,below_perc,over_perc))

    # Second subplot --- instantaneous links' congestion
    sizes = [idle_perc, below_perc, over_perc]
    explode = (0, 0, 0.2)
    ax = fig.add_subplot(2, 2, 3)
    ax.pie(sizes, explode=explode, autopct='%1.1f%%', shadow=True, startangle=90, colors=pie_colors)
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    ax.legend(pie_labels, title="Links' status", bbox_to_anchor=(0.85,1.025), loc="upper left")
    ax.set(aspect="equal", title="Instantaneous links' congestion")
    refresh_figure(fig)


def get_nodes_lists(self):
    """Retrieves host and switch nodes from graph."""
    switch_list = get_switch(self.topology_api_app, None)
    switches = [switch.dp.id for switch in switch_list]
    nodes = self.net.nodes()
    hosts = [node for node in nodes - switches]

    return switches, hosts


def get_edges_list(self):
    """Retrieves edges from graph."""
    links = []
    links = self.net.edges()
    return set(links)


def draw_topology(self):
    """Draws the graph of the topology."""
    fig = plt.figure(4, constrained_layout=True)
    fig.canvas.set_window_title("Topology")
    spec = GridSpec(ncols=4, nrows=4, figure=fig)
    topo_ax = fig.add_subplot(spec[0:1, :], xticklabels=[], yticklabels=[])
    pos = self.pos
    sw_nodelist, h_nodelist = get_nodes_lists(self)
    links = get_edges_list(self)
    fig.clf()
    #nx.draw_networkx(self.net, pos, node_size=600)
    # Nodes
    nx.draw_networkx_nodes(self.net, pos, nodelist=sw_nodelist, **switch_options)
    nx.draw_networkx_nodes(self.net, pos, nodelist=h_nodelist, **host_options)
    nx.draw_networkx_labels(self.net, pos, font_color='white')
    # Edges
    nx.draw_networkx_edges(self.net, pos, edgelist=links, edge_color='k')
    plt.axis('off')
    refresh_figure(fig)



