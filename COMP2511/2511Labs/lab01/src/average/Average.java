package average;

public class Average {
    /**
     * Returns the average of an array of numbers
     * 
     * @param the array of integer numbers
     * @return the average of the numbers
     */
    public float computeAverage(int[] nums) {
        float result = 0;
        for (int i : nums) result += i;
        return result / nums.length;
    }

    public static void main(String[] args) {
        Average aver = new Average();
        System.out.printf("The average is %s\n", aver.computeAverage(new int[] {1, 2, 3, 4, 5, 6}));
    }
}
