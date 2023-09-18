public class GlobalVariable implements Comparable<GlobalVariable> {
    private int offset;

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

}
