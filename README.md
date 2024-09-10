# packet-analyser

## Overview

This program is a multi-threaded intrusion detection system written in C, that intercepts packets on a specified network interface and counts the number of potential SYN attacks, ARP cache poisoning attempts and HTTP requests sent to blacklisted URLs. This is achieved by establishing a loop that indefinitely captures packets, parsing their layers and identifying possible indications of such attacks. The following report will focus on explaining the design decisions and testing of the solution, with an emphasis on the implementation of the threading strategy used, the storage of IP addresses and the testing of the program.

## Threading Strategy

To detect potential attacks on high-traffic networks, it is imperative to use a multi-threaded approach to analyse incoming packets in parallel. This is implemented via a thread pool strategy in which the main program creates a pool of a predefined number of worker threads that are used to process new requests simultaneously. In this strategy, each worker thread retrieves new packet data from a request queue shared amongst all threads and analyses it.

The choice of employing a thread pool strategy was motivated by its key advantages, which become apparent when comparing it with an alternative strategy such as the thread-per-request model. As the name suggests, the thread-per-request model involves creating separate threads to handle each request \[1\]. In this specific application, this would result in a high overhead for each thread, as the number of system calls required would be far greater. Additionally, a high amount of traffic would lead to the creation of a very large number of threads, which would ultimately slow the system down. To illustrate, when listening on a network interface that receives 10,000 packets of data, the program would create 10,000 threads to process each of these packets, which is extremely inefficient and unscalable.

By contrast, the thread pool strategy benefits from the fact that servicing a request with an existing thread is significantly faster than creating a new thread for this purpose \[2\]. This also allows the number of threads in the application to be bound by the size of the thread pool, which is decided by the programmer in advance with a consideration for the available resources. Revisiting the previous example, the program that uses this threading strategy can correctly analyse 10,000 network packets in a matter of seconds.

It can be argued that the thread pool strategy does not make efficient use of CPU cycles and energy as a result of worker threads constantly needing to check the request queue when it is empty. However, the use of a condition variable cond var that is broadcast when a new packet is enqueued ensures that this threading strategy avoids this pitfall.

A crucial decision that directly affects the speed at which packets can be processed is the number of worker threads constituting the thread pool. Given the varied nature of the applications that make use of multi-threading, there is no single value that would be best suited to every case; rather, the optimal size of a thread pool is often determined experimentally. With this in mind, the size of the thread pool in this program was set to 25 threads. When running the program on the DCS machines and sending over 100,000 SYN packets to the loopback interface, it was observed that increasing the size of the thread pool until this value resulted in notable speed improvements. However, using greater than 25 threads resulted in slower overall processing speeds, strengthening the decision regarding the size of the thread pool.

### Storing IP Addresses

Another important design decision is the way in which the IP addresses of captured packets are stored. Given the ambiguity regarding the number of packets that would be captured per session, it was deemed sensible to create a dynamic array. When the capacity of the array is reached, memory is reallocated to increase the capacity by a factor of 1.5. Although many implementations of this data structure use a growth factor value of 2, it is often argued that a growth factor of 1.5 is more efficient due to the fact that resizing the array in this manner reduces the size of the resulting hole in memory \[3\]. This notion is reinforced by the fact that Java’s ArrayLists \[4\], C++’s Vectors \[5\] and Facebook’s FBVector \[6\] all utilise the same resizing strategy, in favour of my decision.

A more efficient solution would be to store IP addresses in a different data structure, such as a Hash Set. This would prevent duplicate addresses from being stored while providing constant time lookup and insertion on average. Even though in this program a linear search is performed before every insertion to ensure duplicates are not present, I felt that implementing a more advanced data structure for this purpose was out of the scope of this coursework, as its focus is on analysing packets and implementing multi-threading, rather than creating an efficient set data structure.

### Testing

The solution was tested on its ability to detect each type of attack using the three scripts provided. After sending different combinations of SYN packets, ARP responses and HTTP requests to blacklisted URLs, the program was observed to consistently detect the correct number of attacks. This proves that the use of mutex locks prevents synchronisation issues arising from race conditions. The effect of the multi-threading strategy was tested by sending up to 100,000 SYN packets and comparing the rate at which the results were obtained when using a thread pool of different sizes. The program was run several times with valgrind \[7\] which reported no memory leaks or overwrites. However, after termination there are 3 bytes of memory that are still reachable stemming from a call to strdup by main; this was not amended as the specification says to not edit this file.

### References

1. D. C. Schmidt and S. Vinoski, “Object interconnections: Comparing alternative programming techniques for multi-threaded corba servers (column 7),” 1996. \[Online\]. Available: https://www.semanticscholar.org/paper/Object-Interconnections-Comparing-Alternative-for-Schmidt-Vinoski/697b2f8884b8de6e17f9bde5bd4854c98058843f.
2. I. Pyarali, M. Spivak, R. Cytron, and D. Schmidt, “Evaluating and optimizing thread pool strategies for real-time corba,” ACM SIGPLAN Notices, vol. 36, Jul. 2001. doi: 10.1145/384197.384226.
3. Wikipedia, Dynamic array — Wikipedia, the free encyclopedia, 2022. \[Online\]. Available: https://en.wikipedia.org/wiki/Dynamic_array.
4. Java.util.arraylist source code, Sun Microsystems, 2009. \[Online\]. Available: http://hg.openjdk.java.net/jdk6/jdk6/jdk/file/e0e25ac28560/src/share/classes/java/util/ArrayList.java.
5. H. Brais, Dissecting the c++ stl vector: Part 3 – capacity & size, 2015. \[Online\]. Available: https://hadibrais.wordpress.com/2013/11/15/dissecting-the-c-stl-vector-part-3-capacity/.
6. Folly/fbvector, Facebook, 2020. \[Online\]. Available: https://github.com/facebook/folly/blob/main/folly/docs/FBVector.md.
7. Valgrind user manual, Valgrind, 2022. \[Online\]. Available: https://valgrind.org/docs/manual/manual.html.
