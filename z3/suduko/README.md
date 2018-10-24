# Suduko

The aim of this exercise is to write code using Z3 which takes an arbitary Suduko board and provided it's possible to solve, solve it.

## Files

### tests.txt

100 random Suduko puzzles I found online, each on a seperate row that looks like this.
```
31.6.......2.......5..9.78......5....9..1..6....4......75.6..3.......4.......7.92
```

### skeleton.py

A simple skeleton file which takes in a file path and selects a random challenge from it, then prints it out. Your challenge is to finish it off so that it prints out a solved suduko board. Example usage.

```
$ python skeleton.py tests.txt 
Selecting random puzzle out of 100 samples
|3|.|.|.|8|.|.|.|.|
|.|.|.|7|.|.|.|.|5|
|1|.|.|.|.|.|.|.|.|
|.|.|.|.|.|.|3|6|.|
|.|.|2|.|.|4|.|.|.|
|.|7|.|.|.|.|.|.|.|
|.|.|.|.|6|.|1|3|.|
|.|4|5|2|.|.|.|.|.|
|.|.|.|.|.|.|8|.|.|

------------------------------


```

The 'Distinct' function is your friend :)

### solution.py

Includes a sample solution to the problem.

```
$ python solution.py tests.txt 
Selecting random puzzle out of 100 samples
|3|9|.|6|.|.|.|.|.|
|.|.|2|.|.|.|.|.|.|
|.|4|.|.|3|.|8|5|.|
|.|.|.|.|.|5|.|.|.|
|.|6|.|.|1|.|.|9|.|
|.|.|.|4|.|.|.|.|.|
|.|1|5|.|6|.|.|3|.|
|.|.|.|.|.|.|7|.|.|
|.|.|.|.|.|7|.|8|2|

------------------------------

|3|9|8|6|5|4|2|7|1|
|5|7|2|1|8|9|6|4|3|
|6|4|1|7|3|2|8|5|9|
|1|8|3|9|7|5|4|2|6|
|2|6|4|8|1|3|5|9|7|
|9|5|7|4|2|6|3|1|8|
|7|1|5|2|6|8|9|3|4|
|8|2|9|3|4|1|7|6|5|
|4|3|6|5|9|7|1|8|2|

```