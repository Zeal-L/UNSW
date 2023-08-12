import time
import cv2
import numpy as np
from flirpy.camera.lepton import Lepton

class Thermal:
    def __init__(self):
        self.camera = Lepton()
        self.timer = time.time()

    def grab(self):
        thermal_data = self.camera.grab().astype(np.float32)
        thermal_data = np.rot90(thermal_data, 1)

        # 原始是160x120
        # 将图像放大3倍, 变成 480x360
        thermal_data = cv2.resize(
            thermal_data, (0, 0), fx=3, fy=3, interpolation=cv2.INTER_NEAREST
        )

        # 重新缩放至8位图像
        thermal_img = (
            255
            * (thermal_data - thermal_data.min())
            / (thermal_data.max() - thermal_data.min())
        )

        # 将热敏图像转换为伪彩色图像
        thermal_img = cv2.applyColorMap(
            thermal_img.astype(np.uint8), cv2.COLORMAP_INFERNO
        )

        self.timer = time.time()

        return thermal_img, thermal_data

    def get_temperature_depth(self, thermal_data, face_coordinates, depth_data):

        if not face_coordinates:
            return 0

        print(len(face_coordinates))

        # 获取face_coordinates里最高的5个温度的值和坐标
        temperatures = [(thermal_data[cor[0], cor[1]], cor) for cor in face_coordinates]
        temperatures = sorted(temperatures, key=lambda x: x[0], reverse=True)[:5]
        temperatures, temperatures_coordinates = zip(*temperatures)

        # print(temperatures / 100 - 273.15)

        avg_temperature = sum(temperatures) / len(temperatures)
        avg_temperature = self.to_celsius(avg_temperature)

        # 统计脸部的平均深度
        face_depth = [depth_data[cor[0], cor[1]] for cor in temperatures_coordinates]

        avg_depth = sum(face_depth) / len(face_depth)

        # mm -> cm
        avg_depth = avg_depth / 10
        # print(avg_depth)

        # 根据脸的距离修正温度 (经验值)
        avg_temperature = avg_temperature + avg_depth * 0.02

        return avg_temperature + 3, avg_depth

    def to_celsius(self, data):
        return data / 100 - 273.15

    def __del__(self):
        self.camera.close()

