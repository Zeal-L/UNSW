package banking;

import java.util.ArrayList;

public class LoggedBankAccount extends BankAccount{

    // Every deposit and withdrawal must make a log of the action.
    private ArrayList<String> log;

    public LoggedBankAccount(String accountNumber) {
        super(accountNumber);
        log = new ArrayList<String>();
    }

    public ArrayList<String> getLog() {
        return log;
    }

    /**
     * @param amount
     * @precondition - amount > 0
     * @postcondition - balance = balance + amount
     */
    @Override
    public void deposit(double amount) {
        if (amount <= 0) return;
        super.deposit(amount);
        log.add("Deposit: " + amount);
    }

    /**
     * @param amount
     * @precondition - amount <= balance, and balance >= 0
     * @postcondition - balance = balance - amount
     */
    @Override
    public void withdraw(double amount) {
        if (amount > getBalance() && getBalance() < 0) return;
        super.withdraw(amount);
        log.add("Withdraw: " + amount);
    }

    @Override
    public String toString() {
        return "LoggedBankAccount{" +
                "log=" + log +
                '}';
    }
}
