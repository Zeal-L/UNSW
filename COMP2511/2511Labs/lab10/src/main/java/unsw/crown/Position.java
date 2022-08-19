package unsw.crown;

import java.util.Objects;

/**
 * @author Braedon Wooding, and @your name
 */
public class Position {
    private int row;
    private int col;

    public Position(int col, int row) {
        this.row = row;
        this.col = col;
    }

    public int getCol() {
        return col;
    }

    public int getRow() {
        return row;
    }

    public static Position midPointPosition(Position a, Position b) {
        return new Position((a.col + b.col) / 2, (a.row + b.row) / 2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(col, row);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Position other = (Position) obj;
        return col == other.col && row == other.row;
    }

    public Position upLeft() {
        return new Position(col - 1, row - 1);
    }

    public Position upRight() {
        return new Position(col + 1, row - 1);
    }

    public Position downLeft() {
        return new Position(col - 1, row + 1);
    }

    public Position downRight() {
        return new Position(col + 1, row + 1);
    }
}
