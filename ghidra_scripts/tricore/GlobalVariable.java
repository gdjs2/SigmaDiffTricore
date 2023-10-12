/**
 * Global variable class, implements {@code Comparable}, {@code equals()} and {@code hashCode()} for {@code TreeSet} support.\
 */
public class GlobalVariable implements Comparable<GlobalVariable> {

    /**
     * The offset of the variable
     */
    private int offset;

    /**
     * Constructor
     * @param offset The offset of the variable
     */
    public GlobalVariable(int offset) {
        this.offset = offset;
    }

    public int getOffset() {
        return offset;
    }

    @Override
    public String toString() {
        return Integer.toString(offset);
    }

    @Override
    public int compareTo(GlobalVariable var) {
        return this.offset - var.offset;
    }

    @Override
    public boolean equals(Object var) {
        if (!(var instanceof GlobalVariable)) return false;
        return this.offset == ((GlobalVariable)var).offset;
    }

    @Override 
    public int hashCode() {
        return Integer.hashCode(offset);
    }

}
