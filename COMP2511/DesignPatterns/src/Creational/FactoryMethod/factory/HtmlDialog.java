package Creational.FactoryMethod.factory;

import Creational.FactoryMethod.buttons.Button;
import Creational.FactoryMethod.buttons.HtmlButton;

/**
 * HTML Dialog will produce HTML buttons.
 */
public class HtmlDialog extends Dialog {

    @Override
    public Button createButton() {
        return new HtmlButton();
    }
}
