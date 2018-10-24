# RNG

The aim of this exercises is to right code in Z3 which given a set of outputs from Java's Random class can recover the initial seed used. Java's class uses an insecure random number generator, based on mutating an initial seed to give a set range of outputs. By taking enough outputs, it is possible to recover the initial seed used with the generator. The code for Java Random class can be found online [here](http://developer.classpath.org/doc/java/util/Random-source.html) and there's a few files included in this directory to help you, along with a sample solution.

## Files

### GenerateSamples.java

An example java class which uses the insecure Random class to generate 20 long values and prints them to stdout.

```
$ javac GenerateSamples.java 
$ java GenerateSamples
```

### rng.py

A python implementation of a subset of Java's Random class. Example usage:
```
$ python rng.py 20 > outputs.txt
```

### skeleton.py
A skeleton solution class which will read a number of a file of sample outputs and load them into a list as integers. You need to finish this file off by adding z3 based code which will recover the seed in use. Example usage:
```
$ python skeleton.py
Loaded 20 sample outputs
```

### solution.py
A demo solution which recovers Random's seed from a list of provided outputs. 
```
$ python solution.py outputs.txt Loaded 20 sample outputs
[seed = 4919]

```