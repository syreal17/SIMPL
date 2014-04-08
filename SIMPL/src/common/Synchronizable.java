package common;

import java.util.concurrent.*;
/*
 * Possible issue: does something special need to happen to the Synchronizable when an exception happens that is not
 * generated by the Synchronizable itself?
 * 
 * Documentation:
 * 	Inspiration:
 * 		http://stackoverflow.com/questions/5222281/how-to-have-one-java-thread-wait-for-the-result-of-another-thread#5224714
 * 	Adapted to be a reusable synchronization method by reading up on:
 * 		http://docs.oracle.com/javase/7/docs/api/java/util/concurrent/CyclicBarrier.html
 * 
 */
/**
 * Synchronizes threads on exactly one write of one thread to one read of another thread
 * @author syreal
 *
 * @param <T> the type of the value that the threads should synchronize on
 */
public class Synchronizable<T> {
	private volatile T value;
	private final CyclicBarrier barrier = new CyclicBarrier(2); //thread 1:UI Loop   thread 2:Client
	
	/**
	 * Set the value first without any synchronization
	 * @param firstValue
	 */
	public Synchronizable(T firstValue){
		this.value = firstValue;
	}
	
	/**
	 * Build the object, but first setting will be synchronized
	 */
	public Synchronizable(){}
	
	/**
	 * Created so that both the getter and setter calls wait at the same barrier
	 * @throws InterruptedException
	 * @throws BrokenBarrierException
	 */
	private void getset_wait() throws InterruptedException, BrokenBarrierException{
		this.barrier.await();
	}
	
	/**
	 * Waits until other thread has set the value and is waiting at barrier
	 * @return the value
	 * @throws InterruptedException thread interruption
	 * @throws BrokenBarrierException if socket dies, this will probably be thrown at UI loop
	 */
	public T get() throws InterruptedException, BrokenBarrierException{
		//wait until value has been set before accessing it
		this.getset_wait();
		return this.value;
	}
	
	/**
	 * Sometimes, the Synchronizable's value needs to be accessed in a non-synchronized way. Viz. sometimes an access
	 * to the value isn't part of inter-thread communication.
	 * @return
	 */
	public T get_bypass(){
		return this.value;
	}
	
	/**
	 * Sets the value and then waits at the barrier, signaling the other thread to access 
	 * @param newValue value to set value to
	 * @throws InterruptedException
	 * @throws BrokenBarrierException
	 */
	public void set(T newValue) throws InterruptedException, BrokenBarrierException{
		//set value
		this.value = newValue;
		//then wait at barrier to signal that access is ok
		this.getset_wait();
	}
	
	public void set_bypass(T newValue){
		this.value = newValue;
	}
}
