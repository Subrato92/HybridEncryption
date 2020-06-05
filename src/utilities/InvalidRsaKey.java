package utilities;

public class InvalidRsaKey extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1064859649016229151L;
	String msg;
	
	public InvalidRsaKey (String msg) {
		this.msg = msg;
	}
	
	@Override
	public String toString() {
		return "[Exception: "+msg+"]";
	}

}
