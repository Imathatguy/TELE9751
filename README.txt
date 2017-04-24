Daniel Paul Iuliano
z3101121
diuliano@gmail.com
Thesis Topic University of New South Wales
Supervisor: Tim Moors
The PC Switch

ReadMe File

In each folder, to compile the program type:

make

To clean up a compilation, type:

make clean

Each component of the switch needs to be run seperately. For the Single switch type:

./clasT & (or ./clasH & for Hash classifier)
./fab &
./schedR & (or ./clasH & for Hash classifier)
./analys (in a seperate window for seperate output)
./gen (make sure it is run last due to other modules dependant on generator starting the flow)