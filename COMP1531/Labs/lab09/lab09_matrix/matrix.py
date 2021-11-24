class Matrix:
    def __init__(self, m, n):
        """Initialises (with zeros) a matrix of dimensions m by n."""
        self.matrix = []
        for i in range(m):
            self.matrix.append([])
            for _ in range(n):
                self.matrix[i].append(0)

    def __str__(self):
        """Returns a string representation of this matrix as integers in the form:
          a b c
          d e f
          g h i
        Used as follows: s = str(m1)
        """
        representation = ""
        for i in range(len(self.matrix)):
            for j in range(len(self.matrix[i])):
                representation += str(self.matrix[i][j])
                if j != len(self.matrix[i]) - 1:
                    representation += " "
            if i != len(self.matrix) - 1:
                representation += '\n'
        return representation

    def get(self, key):
        """Returns the (i,j)th entry of the matrix, where key is the tuple (i, j)

        Used as follows: x = matrix.get((0,0))
        * raises IndexError if (i,j) is out of bounds
        """
        if key[0] >= len(self.matrix) or key[1] >= len(self.matrix[key[0]]) \
            or key[0] < 0 or key[1] < 0:
            raise IndexError("Index out of bounds")
        return self.matrix[key[0]][key[1]]


    def set(self, key, data):
        """Sets the (i,j)th entry of the matrix, where key is the tuple (i, j)

        and data is the number being added.
        Used as follows: matrix.set((0,0), 1)
        * raises IndexError if (i,j) is out of bounds
        * raises TypeError if data is not an integer
        """
        if key[0] >= len(self.matrix) or key[1] >= len(self.matrix[key[0]]) \
            or key[0] < 0 or key[1] < 0:
            raise IndexError("Index out of bounds")
        if not isinstance(data, int):
            raise TypeError("data must be an integer")
        self.matrix[key[0]][key[1]] = data

    def add(self, other):

        """Adds self to another Matrix or integer, returning a new Matrix.

        This method should not modify the current matrix or other.
        Used as follows: m1.add(m2) => m1 + m2
        or: m1.add(3) => m1 + 3
        * raises TypeError if other is not a Matrix object or an integer
        * raises ValueError if the other Matrix does not have the same dimensions
        """
        if isinstance(other, Matrix):
            if len(self.matrix) != len(other.matrix) or len(self.matrix[0]) != len(other.matrix[0]):
                raise ValueError("other must have the same dimensions as self")
            new_matrix = Matrix(len(self.matrix), len(self.matrix[0]))
            for i in range(len(self.matrix)):
                for j in range(len(self.matrix[i])):
                    new_matrix.matrix[i][j] = self.matrix[i][j] + other.matrix[i][j]
            return new_matrix
        if isinstance(other, int):
            if len(self.matrix) == 0:
                return self
            new_matrix = Matrix(len(self.matrix), len(self.matrix[0]))
            for i in range(len(self.matrix)):
                for j in range(len(self.matrix[i])):
                    new_matrix.matrix[i][j] = self.matrix[i][j] + other
            return new_matrix

        raise TypeError("other must be a Matrix or an integer")


    def mul(self, other):

        """Multiplies self with another Matrix or integer, returning a new Matrix.

        This method should not modify the current matrix or other.
        Used as follows: m1.mul(m2) m1 x m2 (matrix multiplication, not point-wise)
        or: m1.mul(3) => m1*3
        * raises TypeError if the other is not a Matrix object or an integer
        * raises ValueError if the other Matrix has incorrect dimensions
        """
        if isinstance(other, Matrix):
            if len(self.matrix) == len(other.matrix) and len(self.matrix[0]) == len(other.matrix[0])\
                or len(self.matrix) == len(other.matrix[0]) \
                or len(self.matrix[0]) == len(other.matrix):
                new_matrix = Matrix(len(self.matrix), len(other.matrix[0]))
                for i in range(len(self.matrix)):
                    for j in range(len(other.matrix[0])):
                        for k in range(len(other.matrix)):
                            new_matrix.matrix[i][j] += self.matrix[i][k] * other.matrix[k][j]
                return new_matrix
            raise ValueError("other must have correct dimensions")
        if isinstance(other, int):
            if len(self.matrix) == 0:
                return self
            new_matrix = Matrix(len(self.matrix), len(self.matrix[0]))
            for i in range(len(self.matrix)):
                for j in range(len(self.matrix[i])):
                    new_matrix.matrix[i][j] = self.matrix[i][j] * other
            return new_matrix

        raise TypeError("other must be a Matrix or an integer")
