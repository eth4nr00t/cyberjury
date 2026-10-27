"""A recorded failure reason names the exception that ended the work."""

from cyberjury.review.failures import exception_reason


def test_exception_reason_names_the_exception_type_and_its_message():
    """A TimeoutError reads as its type name, a colon, and its message."""
    assert exception_reason(TimeoutError("call exceeded the deadline")) == "TimeoutError: call exceeded the deadline"
