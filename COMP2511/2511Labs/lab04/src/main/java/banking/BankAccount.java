package banking;


public class BankAccount {
    private String accountNumber;
    private double balance;
    
    
    public BankAccount(String accountNumber) {
        this.accountNumber = accountNumber;
        this.balance = 0;
    }
    
    public String getAccountNumber() {
        return accountNumber;
    }

    public double getBalance() {
        return balance;
    }
    
    /** 
     * @param amount
     * @precondition - amount > 0
     * @postcondition - balance = balance + amount
     */
    public void deposit(double amount) {
        balance += amount;
    }

    
    /** 
     * @param amount
     * @precondition - amount <= balance, and balance >= 0
     * @postcondition - balance = balance - amount
     */
    public void withdraw(double amount) {
        balance -= amount;
    }
    
}