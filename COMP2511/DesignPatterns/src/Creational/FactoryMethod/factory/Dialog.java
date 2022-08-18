package Creational.FactoryMethod.factory;

import Creational.FactoryMethod.buttons.Button;


// 基础工厂类。请注意，“工厂”只是类的一个角色。它应该有一些需要创建不同产品的核心业务逻辑。
public abstract class Dialog {

    public void renderWindow() {
        Button okButton = createButton();
        okButton.render();
    }

    // 子类将覆盖此方法以创建特定的按钮对象。
    public abstract Button createButton();
}