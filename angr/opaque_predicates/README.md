# Opaque Predicates

Uses Angr to identify opaque predicates (a conditional jump which is always taken or not taken) in x86 assembly.

This was originally inspired by http://zubcic.re/blog/experimenting-with-z3-proving-opaque-predicates and https://github.com/JonathanSalwan/Triton/blob/master/src/examples/python/proving_opaque_predicates.py, aiming to provide an example of using Angr for the same problem.