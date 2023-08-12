import cv2
import mediapipe as mp

class FaceMeshDetector:
    def __init__(self):
        # Initialize MediaPipe face mesh
        self.mp_drawing = mp.solutions.drawing_utils
        self.mp_face_mesh = mp.solutions.face_mesh

        # Initialize face mesh
        self.face_mesh = self.mp_face_mesh.FaceMesh(
            static_image_mode=False,
            max_num_faces=1,
            min_detection_confidence=0.5)

    def grab(self, color_image):

        results = self.face_mesh.process(color_image)

        # Draw face landmarks
        if results.multi_face_landmarks:
            for face_landmarks in results.multi_face_landmarks:
                self.mp_drawing.draw_landmarks(
                    color_image,
                    face_landmarks,
                    self.mp_face_mesh.FACEMESH_CONTOURS,
                    landmark_drawing_spec=self.mp_drawing.DrawingSpec(
                        color=(0, 255, 0),
                        thickness=1,
                        circle_radius=1),
                    connection_drawing_spec=self.mp_drawing.DrawingSpec(
                        color=(0, 255, 0),
                        thickness=1))

        # 获取人脸关键点
        face_landmarks_list = []
        if results.multi_face_landmarks:
            for lmk in results.multi_face_landmarks[0].landmark:
                x, y = int(lmk.x * color_image.shape[0]), int(lmk.y * color_image.shape[1])
                # 过滤掉超出图像范围的点
                if x < 0 or y < 0 or x >= color_image.shape[0] or y >= color_image.shape[1]:
                    continue
                face_landmarks_list.append((x, y))

            # print(face_landmarks_list[0], len(face_landmarks_list))

        return face_landmarks_list

    def __del__(self):
        # Release resources
        self.face_mesh.close()

