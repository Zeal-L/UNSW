package Creational.FactoryMethod.factory;

import Creational.FactoryMethod.buttons.Button;
import Creational.FactoryMethod.buttons.WindowsButton;

/**
 * Windows Dialog will produce Windows buttons.
 */
public class WindowsDialog extends Dialog {

    @Override
    public Button createButton() {
        return new WindowsButton();
    }
}