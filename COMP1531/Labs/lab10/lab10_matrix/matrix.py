class Matrix:
    def __init__(self, m, n):
        """
        Initialises a matrix of dimensions m by n.
        """
        self.m = m
        self.n = n
        self.matrix = [[0 for x in range(n)] for y in range(m)]

    def validate_data(self, data, n):
        if len(data) != n:
            raise ValueError

        if not (isinstance(data, list) or isinstance(data, tuple)):
            raise TypeError

        for item in data:
            if not isinstance(item, int):
                raise TypeError

    def __getitem__(self, key):
        """
        Returns the (i,j)th entry of the matrix, where key is the tuple (i,j).
        i or j may be Ellipsis (...) indicating that the entire i-th row
        or j-th column should be selected. In this case, this method returns a
        list of the i-th row or j-th column.
        Used as follows: x = matrix[0,0] || x = matrix[...,1] || x = matrix[0,...]
         * raises IndexError if (i,j) is out of bounds
         * raises TypeError if (i,j) are both Ellipsis
        """
        i, j = key
        if i is Ellipsis and j is Ellipsis:
            raise TypeError
        elif j is Ellipsis:
            return list(self.matrix[i])
        elif i is Ellipsis:
            return [self.matrix[x][j] for x in range(self.m)]

        if i < 0 or j < 0 or i > self.m or j > self.n:
            raise IndexError

        return self.matrix[i][j]

    def __setitem__(self, key, data):
        """
        Sets the (i,j)th entry of the matrix, where key is the tuple (i,j)
        and data is the number being added.
        One of i or j may be Ellipsis (...) indicating that the entire i-th row
        or j-th column should be replaced. In this case, data should be a list
        or a tuple of integers of the same dimensions as the equivalent matrix
        row or column. This method then replaces the i-th row or j-th column
        with the contents of the list or tuple
        Used as follows: matrix[0,0] = 1 || matrix[...,1] = [4,5,6] || matrix[0,...] = (1,2)
         * raises IndexError if (i,j) is out of bounds
         * raises TypeError if (i,j) are both Ellipsis
         * if i and j are integral, raises TypeError if data is not an integer
         * if i or j are Ellipsis, raises TypeError if data is not a list or tuple of integers
         * if i or j are Ellipsis, raises ValueError if data is not the correct size
        """
        i, j = key

        if i is Ellipsis and j is Ellipsis:
            raise TypeError

        if j is Ellipsis:
            self.validate_data(data, self.n)
            self.matrix[i] = list(data)
            return

        elif i is Ellipsis:
            self.validate_data(data, self.m)

            for x in range(self.m):
                self.matrix[x][j] = data[x]
            return

        if i < 0 or j < 0 or i > self.m or j > self.n:
            raise IndexError

        if not isinstance(data, int):
            raise TypeError

        self.matrix[i][j] = data

    def __iadd__(self, other):
        """
        Adds other to this matrix, modifying this matrix object and returning self
        Used as follows: m1 += m2 ||  m1 += 3
         * raises TypeError if other is not a Matrix object or an integer
         * raises ValueError if adding another Matrix and it does not have the same dimensions as this matrix
        """
        self = self + other
        return self

    def __add__(self, other):
        """
        Adds this matrix to other, returning a new matrix object.
        This method should not modify the current matrix or other.
        Used as follows: m1 + m2 ||  m1 + 3
         * raises TypeError if other is not a Matrix object or an integer
         * raises ValueError if adding another Matrix and it does not have the same dimensions as this matrix
        """
        if isinstance(other, int):
            new = Matrix(self.m, self.n)
            for row in range(self.m):
                for col in range(self.n):
                    new[row, col] = self[row, col] + other

            return new

        elif isinstance(other, Matrix):
            new = Matrix(self.m, self.n)

            if self.get_dimensions() != other.get_dimensions():
                raise ValueError

            for row in range(self.m):
                for col in range(self.n):
                    new[row, col] = self[row, col] + other[row, col]

            return new

        raise TypeError

    def __mul__(self, other):
        """Multiplies self with another Matrix or integer, returning a new Matrix.

        This method should not modify the current matrix or other.
        Used as follows: m1*m2 => m1.__mul__(m2) (matrix multiplication, not point-wise)
        or: m1*3 => m1.__mul__(3)
        * raises TypeError if the other is not a Matrix object or an integer
        * raises ValueError if the other Matrix has incorrect dimensions
        """
        if isinstance(other, int):
            new = Matrix(self.m, self.n)
            for row in range(self.m):
                for col in range(self.n):
                    new[row, col] = self[row, col] * other
            return new

        elif isinstance(other, Matrix):
            m, n = self.get_dimensions()
            o, p = other.get_dimensions()

            if n != o:
                raise ValueError

            new = Matrix(m, p)
            # print('n=',n,'p=',p)
            for a in range(self.m):
                for b in range(p):
                    entry = 0
                    for c in range(n):
                        entry += self[a, c] * other[c, b]
                        # print((a, c), (c, b), '-', entry)
                    new[a, b] = entry
            return new

        raise TypeError

    def get_dimensions(self):
        return (self.m, self.n)

    def __str__(self):
        """
        Returns a string representation of this matrix in the form:
          a b c
          d e f
          g h i
        Used as follows: s = str(m1)
        """
        res = []
        for row in self.matrix:
            res.append(' '.join([str(n) for n in row]))
        return '\n'.join(res)

    def transpose(self):
        """
        Returns a new matrix that is the transpose of this Matrix object
        This method should not modify the current matrix.
        """
        new = Matrix(self.n, self.m)
        for row in range(self.m):
            for col in range(self.n):
                new[col, row] = self[row, col]
        return new

    def copy(self):
        """
        Returns a new Matrix that is an exact and independent copy of this one
        This method should not modify the current matrix.
        """
        new = Matrix(self.m, self.n)
        for row in range(self.m):
            for col in range(self.n):
                new[row, col] = self[row, col]
        return new
