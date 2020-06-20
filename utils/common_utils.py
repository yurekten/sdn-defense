import math


def entropy(array):

    total_entropy = 0

    for i in array:
        total_entropy += -i * math.log(2, i)

    return total_entropy