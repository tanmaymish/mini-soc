"""
Detection efficacy benchmark.

The unit tests answer "does this rule fire when I hand it exactly the thing it
looks for". That is necessary and it is not what a detection engineer is judged
on. The questions that matter are:

  - Of everything this rule alerts on, how much is real?      (precision)
  - Of the attacks it should catch, how many does it catch?   (recall)
  - How much noise does it make on a normal working day?      (false positives)

This package replays a labelled corpus of benign and malicious traffic through
the real DetectionEngine and answers them.
"""
