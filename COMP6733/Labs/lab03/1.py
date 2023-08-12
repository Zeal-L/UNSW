import numpy as np
import matplotlib.pyplot as plt

# RSSI values collected from BLE packets sent from Arduino board
rssi = [-33, -42, -55, -54, -66, -70, -67, -77, -83, -85]

# Distance values corresponding to the RSSI values
distance = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

pathloss = np.polyfit(rssi, distance, 1)
print(pathloss)

# Plotting the data and the fitted line
plt.scatter(rssi, distance)
plt.plot(rssi, np.polyval(pathloss, rssi), 'r')
plt.xlabel('RSSI')
plt.ylabel('Distance')

plt.title('RSSI vs Distance')
plt.show()

