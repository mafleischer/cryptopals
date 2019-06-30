class ParamValueError(Exception):
    """
    Raised when a value that is erroneous is passed as a parameter
    """
    pass

class ParamValueNotHandledError(Exception):
    """
    "Placeholder" exception for for which code to handle properly it
    is not yet written.
    """
    pass

class ParamClashError(Exception):
    """
    Raised when values are passed that individually are not erroneous but
    cannot be together combined. E.g. looking for a substring of length
    greater than the legnth of the string
    """
    pass