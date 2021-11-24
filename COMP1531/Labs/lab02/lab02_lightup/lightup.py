def board_is_happy(board):
  return False  # TODO


def board_is_solved(board):
  return False  # TODO


def get_board_state(board):
  if board_is_happy(board):
    if board_is_solved(board):
      return 'solved'
    else:
      return 'happy'
  else:
    return 'unhappy'
