package Structural.DecoratorPattern;

import Structural.DecoratorPattern.decorators.*;

public class Main {
    public static void main(String[] args) {
        String filePath = "src/Structural/DecoratorPattern/OutputDemo.txt";
        String salaryRecords = "Name,Salary\nJohn Smith,100000\nSteven Jobs,912000";
        DataSourceDecorator encoded = 
                new CompressionDecorator(
                    new EncryptionDecorator(
                        new EncryptionDecorator(
                            new FileDataSource(filePath))));
        
        encoded.writeData(salaryRecords);
        DataSource plain = new FileDataSource(filePath);

        System.out.println("- Input ----------------");
        System.out.println(salaryRecords);
        System.out.println("- Encoded Twice --------------");
        System.out.println(plain.readData());
        System.out.println("- Decoded --------------");
        System.out.println(encoded.readData());
    }
}
