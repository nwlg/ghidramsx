package org.dihalt;

public enum MegaRomType {
    PLAIN("PLAIN"),
    ASCII16("ASCII16"),
    ASCII8("ASCII8"),
    KONAMI4("KONAMI4"),
    KONAMI5("KONAMI5");

    private final String description;

    MegaRomType(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    //get enum by name
    public static MegaRomType fromName(String name) {
        for (MegaRomType type : values()) {
            if (type.name().equalsIgnoreCase(name) || type.description.equalsIgnoreCase(name)) {
                return type;
            }
        }
        return null; // noy found
    }
}
