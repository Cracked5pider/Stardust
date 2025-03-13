SECTIONS
{
    .text :
    {
        *( .text$A );
        *( .text$B );
        *( .rdata* );
        *( .text$C );
        *( .text$E );
    }
}
