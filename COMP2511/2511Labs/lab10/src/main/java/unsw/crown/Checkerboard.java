package unsw.crown;

/**
 * @author Braedon Wooding, and @your name
 */
public class Checkerboard {
    public static final int BOARD_SIZE = 8;
    private Checker[][] board;

    public Checkerboard(boolean quackering) {
        this.board = new Checker[BOARD_SIZE][BOARD_SIZE];
        for (int col = 0; col < BOARD_SIZE; col++) {
            for (int row = 0; row < BOARD_SIZE; row++) {
                if (row % 2 != col % 2 && (row < 3 || row > 4)) {
                    // dark square
                    board[col][row] = new Checker(row < 3 ? CheckerColor.WHITE : CheckerColor.RED, quackering && (row == 0 || row == BOARD_SIZE - 1));
                }
            }
        }
    }

    public void moveChecker(Position position, Position endPosition) {
        if (isInBounds(position) && isInBounds(endPosition)) {
            board[endPosition.getCol()][endPosition.getRow()] = board[position.getCol()][position.getRow()];
            if (endPosition.getRow() == 0 || endPosition.getRow() == BOARD_SIZE - 1) {
                board[endPosition.getCol()][endPosition.getRow()].setCrowned();
            }

            board[position.getCol()][position.getRow()] = null;

            Position midPoint = Position.midPointPosition(position, endPosition);
            if (midPoint.equals(endPosition) == false && midPoint.equals(position) == false) {
                board[midPoint.getCol()][midPoint.getRow()] = null;
            }
        }
    }

    public boolean isInBoundsAndEmpty(Position pos) {
        return isInBounds(pos) && getPieceAt(pos) == null;
    }

    public boolean isInBounds(Position pos) {
        int row = pos.getRow(), col = pos.getCol();
        return row >= 0 && col >= 0 && row < BOARD_SIZE && col < BOARD_SIZE;
    }

    public Checker getPieceAt(Position pos) {
        int row = pos.getRow(), col = pos.getCol();
        if (row >= 0 && col >= 0 && row < BOARD_SIZE && col < BOARD_SIZE) {
            return board[col][row];
        } else {
            throw new IllegalArgumentException("Row/Col are out of bounds");
        }
    }
}
