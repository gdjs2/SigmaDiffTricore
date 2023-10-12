/**
 * compare two nodes accroding to their value string
 * 
 * @author yijiufly
 *
 */
public class MyComparator implements java.util.Comparator<Node> {

	private int referenceLength;

	public MyComparator(String reference) {
		super();
		this.referenceLength = reference.length();
	}

	public int compare(Node s1, Node s2) {
//        int dist1 = Math.abs(s1.toString().length() - referenceLength);
//        int dist2 = Math.abs(s2.toString().length() - referenceLength);
		return s1.toString().compareTo(s2.toString());
//        return dist1 - dist2;
	}
}