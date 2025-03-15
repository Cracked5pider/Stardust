SECTIONS
{
    .text :
    {
        *( .text$A );
        *( .text$B );
        *( .rdata* );
        *( .text$C );
    }
}
