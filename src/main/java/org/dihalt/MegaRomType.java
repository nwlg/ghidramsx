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

    // Cache for faster lookup
    private static final java.util.Map<String, MegaRomType> BY_NAME = new java.util.HashMap<>();

    static {
        for (MegaRomType type : values()) {
            BY_NAME.put(type.name().toUpperCase(), type);
            // Ensure description is also mapped in uppercase for case-insensitive lookup
            BY_NAME.put(type.getDescription().toUpperCase(), type);
        }
    }

    // get enum by name
    public static MegaRomType fromName(String name) {
        if (name == null)
            return null;
        return BY_NAME.get(name.toUpperCase());
    }
}
