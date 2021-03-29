# PicoLisp tis.config file generator
(de prn (F M)
   (prinl "{")
   (printsp "name" ': (pack F " - " M))
   (prinl ",")
   (printsp "files" ': "all")
   (prinl ",")
   (printsp "cpp-extra-args" ': "-I. -I kremlib/dist/minimal")
   (prinl ",")
   (printsp "machdep" ': (text M))
   (prinl ",")
   (printsp "main" ': (text F))
   (prinl)
   (prinl "}") )
(setq
   *M
   (quote
      gcc_sparc_64 gcc_sparc_32
      gcc_x86_32 gcc_x86_64 gcc_x86_16 
      gcc_armeb_eabi gcc_arm_eabi gcc_aarch64 aarch64eb
      gcc_rv64ifdq gcc_rv32ifdq
      gcc_mips_o32 gcc_mips_n32 gcc_mips_64 gcc_mipsel_64
      gcc_mipsel_n32 gcc_apple_ppc_32      
   )
   *F
   (quote
      p1305
   )
   *L
   (make
      (for F *F
         (for M *M
            (link (cons F M)) ) ) ) )
(out "tis.config"
   (prinl "// Auto genetated file")
   (prinl "[")
   (for (L *L L (cdr L))
      (let (F (caar L)  M (cdar L))
         (prn F M)
         (and (cdr L) (prinl ",")) ) )
   (prinl "]") )
(bye)
