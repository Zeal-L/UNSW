package Creational.AbstractFactory.factories;

import Creational.AbstractFactory.buttons.Button;
import Creational.AbstractFactory.buttons.MacOSButton;
import Creational.AbstractFactory.checkboxes.Checkbox;
import Creational.AbstractFactory.checkboxes.MacOSCheckbox;

/**
 * Each concrete factory extends basic factory and responsible for creating
 * products of a single variety.
 */
public class MacOSFactory implements GUIFactory {

    @Override
    public Button createButton() {
        return new MacOSButton();
    }

    @Override
    public Checkbox createCheckbox() {
        return new MacOSCheckbox();
    }
}