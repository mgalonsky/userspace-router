#                                                                               
# Makefile for Networks lab3                                 
#                           
# Authors: Melissa Galonsky and Helen Woodward
#                                                    

# ----- Make Macros -----                                                       

# OPTFLAGS  =   -O2                                                             
DEFINES   =
INCLUDES  = 
CXXFLAGS  =	-g -std=c++11 -Wall -Wextra -pedantic $(DEFINES) $(OPTFLAGS) $(INCLUDES) 
CXX       =	g++

TARGETS   =	userspace_router
FILETRANSFER_OBJS = userspace_router.o 

# ----- Make Rules -----                                                        

all:    $(TARGETS)

userspace_router: userspace_router.o
	$(CXX) -o userspace_router userspace_router.o $(CXXFLAGS)

clean:
	rm -f $(TARGETS) *.o

# ------ Dependences (.cpp -> .o using default Makefile rule) -----             

userspace_router.o: userspace_router.cpp
