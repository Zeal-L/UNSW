我叫 Zeal。

在这项任务中，我使用 YOLO 模型来完成分类和检测任务。

Yolo 是 "你只看一次 "的缩写。它是最先进的实时物体检测系统。到 2023 年，YOLO 已经发展到第 8 版。根据官方介绍，YOLOv8 是一个 SOTA 模型，它建立在 YOLO 以前版本的成功基础上，并引入了新的功能和改进，以进一步提高性能和灵活性。

从图中可以看出，与 YOLOv5 相比，YOLOv8 的精确度有了很大提高。因此，我决定试试这个模型

My name is Zeal.

In this task I used the YOLO model for both classification and detection tasks.

Yolo is short for You Only Look Once. It is a state-of-the-art, real-time object detection model. By 2023 YOLO has evolved to v8. As per the official description, YOLOv8 is a SOTA model that builds on the success of previous YOLO versions and introduces new features and improvements to further enhance performance and flexibility.

As you can see from the graph, the accuracy of YOLOv8 is very much improved compared to YOLOv5. So I decided to try this model

为了使用 COCO 数据集训练 YOLO 算法，我们需要将 COCO 数据集的标注信息转换为 YOLO 格式的标签。

In order to use the COCO dataset for training the YOLO model, we need to convert the annotation information of the COCO dataset into labels in YOLO format.


在机器学习中，数据集的大小和质量对模型的训练和性能至关重要。数据集越大，模型能够学习的特征和模式就越多，从而提高模型的准确性和泛化能力。

In machine learning, the size and quality of the dataset is critical to the training and performance of the model. The larger the dataset, the more features and patterns the model is able to learn, which improves the accuracy and generalization of the model.

我们对提供的企鹅和海龟图像进行了数据增强，包括添加高斯噪声和翻转图像。这样做是为了扩大训练集，增加数据集的规模和多样性，从而提高模型的准确性和泛化能力。然后将训练集从原来的 500 张图像增加到 1000 张图像。

We performed data enhancement on the provided images of penguins and turtles, including adding Gaussian noise and flipping the images. This was done to expand the training set and increase the size and diversity of the dataset, thus improving the accuracy and generalization of the model. The training set is then increased from the original 500 to 1000 images.

我选择训练了100 epochs，你可以很清楚的看到我们模型的loss值慢慢的越来越小，从最开始的1.2到最后的0.2.这意味着表示模型学习到更准确地预测目标的位置，边界框的位置逐渐接近真实值。可以看到precision也从最开始的60到了最后的98%

I chose to train for 100 epochs, and you can clearly see that the loss value of our model is slowly getting smaller and smaller, from 1.2 at the beginning to 0.2 at the end.This means that it indicates that the model learns to predict the position of the target more accurately, and the position of the bounding box is gradually approaching to the real value. You can see that the precision also went from 60 at the beginning to 98% at the end,