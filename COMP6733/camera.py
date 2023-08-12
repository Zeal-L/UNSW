import time
import cv2
import numpy as np
from thermal import Thermal
from faceMesh import FaceMeshDetector
from rgb_depth import RGB_Depth

thermal = Thermal()
faceMesh = FaceMeshDetector()
rgb_depth = RGB_Depth()


def get_angle_offset(face_landmarks_list):
    # Get the x-coordinate of the center of the face
    x_center = (face_landmarks_list[0][0][0] + face_landmarks_list[0][32][0]) / 2

    # Set the width of the image
    img_width = 360

    # Calculate the angle offset
    return (x_center - img_width / 2) / img_width * 60


faceMesh_img, depth_data = rgb_depth.grab()

thermal_img, thermal_data = thermal.grab()

# 选择thermal_img中的四个点
rect1 = cv2.selectROI('thermal_img', thermal_img, False)
cv2.destroyAllWindows()

# 选择faceMesh_img中的四个点
rect2 = cv2.selectROI('faceMesh_img', faceMesh_img, False)
cv2.destroyAllWindows()

# 计算透视变换矩阵
src_pts = np.array([[rect1[0], rect1[1]], [rect1[0] + rect1[2], rect1[1]], [rect1[0] + rect1[2], rect1[1] + rect1[3]], [rect1[0], rect1[1] + rect1[3]]], dtype=np.float32)
dst_pts = np.array([[rect2[0], rect2[1]], [rect2[0] + rect2[2], rect2[1]], [rect2[0] + rect2[2], rect2[1] + rect2[3]], [rect2[0], rect2[1] + rect2[3]]], dtype=np.float32)
M = cv2.getPerspectiveTransform(src_pts, dst_pts)

print(M)

M = np.array(
        [
            [1.27480916e+00, -3.18284929e-17, 1.11709924e+02],
            [-8.18907323e-17, 1.33566434e+00, -1.08748252e+02],
            [-2.83978552e-19, -0.00000000e+00, 1.00000000e+00],
        ]
    ).astype(np.float32)


while True:
    thermal_img, thermal_data = thermal.grab()

    color_image, depth_data = rgb_depth.grab()

    face_landmarks_list = faceMesh.grab(color_image)

    # 对thermal_img进行透视变换
    aligned_thermal_img = cv2.warpPerspective(
        thermal_img, M, (color_image.shape[1], color_image.shape[0])
    )

    aligned_thermal_data = cv2.warpPerspective(
        thermal_data, M, (color_image.shape[1], color_image.shape[0])
    )

    # 在图像顶部显示最小和最大温度以及帧速率
    text = "Tmin = {:+.1f} Tmax = {:+.1f} FPS = {:.2f}".format(
        thermal.to_celsius(thermal_data.min()),
        thermal.to_celsius(thermal_data.max()),
        1 / (time.time() - thermal.timer),
    )

    cv2.putText(
        aligned_thermal_img,
        text,
        (5, 15),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.45,
        (255, 255, 255),
        1,
    )

    if face_landmarks_list.__len__() != 0:
        T , D = thermal.get_temperature_depth(aligned_thermal_data, face_landmarks_list, depth_data)

        cv2.putText(
            aligned_thermal_img,
            "T={:.1f}, D={:.1f}cm".format(T, D),
            (15, 50),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.8,
            (0, 0, 255),
            2,
        )

    # Overlay thermal_img on faceMesh_img
    alpha = 0.5
    overlay = cv2.addWeighted(color_image, alpha, aligned_thermal_img, 1 - alpha, 0)

    # show the image
    cv2.imshow("overlay", overlay)
    # cv2.imshow("thermal", thermal_img)
    # cv2.imshow("faceMesh", faceMesh_img)

    if cv2.waitKey(5) & 0xFF == ord("q"):
        break