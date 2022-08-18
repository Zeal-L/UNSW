package Creational.AbstractFactory.factories;

import Creational.AbstractFactory.buttons.Button;
import Creational.AbstractFactory.buttons.WindowsButton;
import Creational.AbstractFactory.checkboxes.Checkbox;
import Creational.AbstractFactory.checkboxes.WindowsCheckbox;

/**
 * Each concrete factory extends basic factory and responsible for creating
 * products of a single variety.
 */
public class WindowsFactory implements GUIFactory {

    @Override
    public Button createButton() {
        return new WindowsButton();
    }

    @Override
    public Checkbox createCheckbox() {
        return new WindowsCheckbox();
    }
}
