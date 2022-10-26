# malloc

TODO: Come up with a real name for this.

An implementation of malloc for POSIX-compliant systems, created for my operating systems class.
This isn't particularly good currently, but it does at least work as a drop-in replacement for simple single-threaded programs. It is not thread-safe at the moment and you will run into data race issues that could corrupt the heap.

Once this is reasonably complete, it could function as a good tool for studying dynamic memory allocation.
