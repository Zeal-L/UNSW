package Creational.AbstractFactory.factories;

import Creational.AbstractFactory.buttons.Button;
import Creational.AbstractFactory.checkboxes.Checkbox;

/**
 * Abstract factory knows about all (abstract) product types.
 */
public interface GUIFactory {
    Button createButton();
    Checkbox createCheckbox();
}
