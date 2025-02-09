import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import folium
import requests

class TrafficVisualizer:
    def __init__(self):
        self.fig, (self.ax1, self.ax2) = plt.subplots(2, 1, figsize=(12, 10))
        plt.ion()  # Enable interactive mode
        
    def update_live_graph(self, data_points):
        self.ax1.clear()
        self.ax2.clear()
        
        # Traffic graph
        self.ax1.plot(data_points['time'], data_points['sent'], label='Sent', color='blue')
        self.ax1.plot(data_points['time'], data_points['received'], label='Received', color='green')
        self.ax1.set_title('Live Network Traffic')
        self.ax1.set_ylabel('KB/s')
        self.ax1.legend()
        
        # Country distribution pie chart
        countries = data_points.get('countries', {})
        if countries:
            labels = list(countries.keys())
            sizes = list(countries.values())
            self.ax2.pie(sizes, labels=labels, autopct='%1.1f%%')
            self.ax2.set_title('Data Distribution by Country')
        
        plt.draw()
        plt.pause(0.1)
