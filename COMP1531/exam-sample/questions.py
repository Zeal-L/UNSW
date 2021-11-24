'''
The backend for the lecture question asking application.

Each question is assigned an ID number when it is submitted to the app. This ID
can then be used to like and dismiss the question. The numbers are always
positive, but otherwise follow no defined ordering or structure. Questions have
the same ID from when they are submitted till they are dismissed.

When questions are first submitted, they have 0 likes.
'''

# Put any global variables your implementation needs here
unanswered = {}
id_counter = 0

def submit(question):
    '''
    Submits a question to the service.

    Returns the ID of the question but yields a ValueError if question is an
    empty string or exceeds 280 characters in length.
    '''
    global id_counter
    if not question or len(question) > 280:
        raise ValueError("Invalid question")

    unanswered[id_counter] = {"question": question, "likes": 0}
    id_counter += 1
    return id_counter - 1

def questions():
    '''
    Returns a list of all the questions.

    Each question is represented as a dictionary of {id, question, likes}.

    The list is in order of likes, with the most liked questions first. When
    questions have the same number of "likes", their order is not defined.
    '''
    # Hint: For this question, there are still marks available if the returned
    # list is in the wrong order, so do not focus on that initially.
    result = []
    for id, q in unanswered.items():
        result.append({"id": id, "question": q["question"], "likes": q["likes"]})
    return sorted(result, key=(lambda x: x["likes"]), reverse=True)

def clear():
    '''
    Removes all questions from the service.
    '''
    global unanswered
    unanswered = {}

def like(id):
    '''
    Adds one "like" to the question with the given id.

    It does not return anything but raises a KeyError if id is not a valid
    question ID.
    '''
    unanswered[id]["likes"] += 1

def dismiss(id):
    '''
    Removes the question from the set of questions being stored.

    It does not return anything but raises a KeyError if id is not a valid
    question ID.
    '''
    del unanswered[id]
