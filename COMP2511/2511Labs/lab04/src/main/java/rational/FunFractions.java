package rational;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

/**
 * A client of the Rational class / ADT
 * @author Nick Patrikeos
 */
public class FunFractions {
    
    private static final String[] OPERATORS = { "+", "-", "×", "÷"};
    private static final ArrayList<String> NUMERICS = new ArrayList<String>(Arrays.asList(new String[] {"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"}));

    /*private static Rational randomRational() {
        int numerator = (int) (Math.random() * 10.0);
        int denominator = (int) (Math.random() * 10.0 + 1);
        return new Rational(numerator, denominator);
    }
    
    public static void play() {
        String userAnswer = "0";
        Random rand = new Random();
        Scanner scanner = new Scanner(System.in);

        while (!userAnswer.equals("")) {
            Rational num1 = randomRational();
            Rational num2 = randomRational();
            String operator = OPERATORS[rand.nextInt(4)];
            System.out.println(String.format("\nWhat is %s %s %s?", num1, operator, num2));

            Rational answer;
            switch (operator) {
                case "+":
                    answer = num1.add(num2); break;
                case "-":
                    answer = num1.subtract(num2); break;
                case "×":
                    answer = num1.multiply(num2); break;
                case "÷":
                    answer = num1.divide(num2); break;
                default: 
                    answer = null; break;
            }

            List<Rational> answers = new ArrayList<Rational>(Arrays.asList(new Rational[] {answer, randomRational(), randomRational(), randomRational()}));
            Collections.shuffle(answers);
            
            for (int i = 0; i < answers.size(); i++) {
                System.out.println(String.format("%s) %s", i, answers.get(i)));
            }

            System.out.print("> ");
            userAnswer = scanner.nextLine();

            if (!userAnswer.equals("") && isNumeric(userAnswer) && Integer.parseInt(userAnswer) < 4) {
                int i = Integer.parseInt(userAnswer);
                Rational userAnswerRational = answers.get(i);

                if (userAnswerRational.equals(answer)) {
                    System.out.println("Correct!");
                } else {
                    System.out.println(String.format("Incorrect. The correct answer was: %s", answer));
                }
            } else {
                System.out.println(String.format("Invalid input. The correct answer was: %s", answer));
            }
        }

        scanner.close();
    }

    private static boolean isNumeric(String answer) {
        return NUMERICS.contains(answer);
    }
    
    public static void main(String[] args) {
        FunFractions.play();
    }*/
}