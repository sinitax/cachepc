OUTPUT_FORMAT(binary)

SECTIONS
{
    .text : {
        . = 0;
        *(.text)
    }

    .data : {
        *(.data)
    }
}
