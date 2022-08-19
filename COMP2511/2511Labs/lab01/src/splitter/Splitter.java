package splitter;

import java.io.*;
public class Splitter {
    public static void main(String[] args) throws IOException {
        System.out.printf("Enter a message: \n");
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String[] words = br.readLine().split(" ");
        for (String word : words) {
            System.out.printf("%s\n", word);
        }
    }
}
