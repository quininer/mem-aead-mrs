use byteorder::{ ByteOrder, LittleEndian };
use crate::{ U, LENGTH, STATE_LENGTH };


pub trait Tag {
    const TAG: U;
}

pub mod tags {
    use super::U;
    use super::Tag;

    macro_rules! tags {
        ( $( $( #[$attr:meta] )* $name:ident => $val:expr ),+ ) => {
            $(
                $( #[$attr] )*
                pub enum $name {}

                impl Tag for $name {
                    const TAG: U = $val;
                }
            )+
        }
    }

    tags!{
        Abs => 0x00,
        Enc => 0x01
    }
}

#[inline]
pub fn with<F>(arr: &mut [U; LENGTH], f: F)
    where F: FnOnce(&mut [u8; STATE_LENGTH])
{
    #[inline]
    fn transmute(arr: &mut [U; LENGTH]) -> &mut [u8; STATE_LENGTH] {
//        unsafe { mem::transmute(arr) }
        unsafe { &mut *(arr as *mut [U; LENGTH] as *mut [u8; STATE_LENGTH]) }
    }

    #[inline]
    fn le_from_slice(arr: &mut [U; LENGTH]) {
        LittleEndian::from_slice_u64(arr);
    }

    le_from_slice(arr);
    f(transmute(arr));
    le_from_slice(arr);
}
