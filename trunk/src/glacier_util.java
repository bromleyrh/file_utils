/*
 * glacier_util.java
 */

class inventory {
    private String file;

    public inventory(String _file)
    {
        file = _file;
    }

    public void parse()
    {
        System.out.format("%s\n", file);
    }
}

public final class glacier_util {
    public static void main(String[] args)
    {
        String file;

        if (args.length == 0) {
            System.err.format("Must specify file\n");
            System.exit(1);
        }
        file = args[0];

        inventory i = new inventory(file);
        i.parse();
        System.exit(0);
    }
}

/* vi: set expandtab sw=4 ts=4: */
