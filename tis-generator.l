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
   (printsp "raw_options" ':)
   (prin "{ ")
   (printsp "-val-timeout" ': 10800)
   (prin ", ")
   (printsp "-no-results" ': "true")
   (prinl "} ,")
   (printsp "main" ': (text F))
   (prinl)
   (prinl "}") )
(setq
   *M
   (quote
      sparc_64 x86_32
      # sparc_64 sparc_32
      # x86_32 x86_64 x86_16
      # armeb_eabi arm_eabi aarch64 aarch64eb
      # rv64ifdq rv32ifdq
      # mips_o32 mips_n32 mips_64 mipsel_64
      # mipsel_n32 apple_ppc_32
   )
   *F
   (quote
      # p1305 x25519 sha512 blake2b hmac
      sign_check_ed25519
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
