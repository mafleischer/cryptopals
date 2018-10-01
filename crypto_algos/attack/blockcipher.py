from crypto_algos.helpers import stateGenerator

def hasBlockRepetition(bstr):
    """
    Detect block repetition in byte string

    Returns: True if repetition found
            false otherwise
    """

    state_iter = stateGenerator(bstr)
    state_list = [state for state in state_iter]
    for state in state_list:
        if state_list.count(state) > 1:
            return True
    return False

    # is it theoretically possible to have repetition by chance with cbc?

    # maxkey = max(state_counts.keys(), key=(lambda k: state_counts[k]))
    # if state_counts[maxkey] >= threshold:
    #    bstrs_w_highest_state_count[bstr] = state_counts[maxkey]
